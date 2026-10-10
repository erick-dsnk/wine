#!/usr/bin/env python3
# Benign disposable AMD64 proof runner. LGPL 2.1 or later.
import datetime, hashlib, json, os, pathlib, subprocess, sys, time, re

root = pathlib.Path(os.environ['A1B_PROOF_ROOT']).resolve()
sdk = 'registry.gitlab.steamos.cloud/proton/steamrt4/sdk/x86_64@sha256:97526b794ce1a9bed5f891084462260b3a02399569f7438a3a57b5a253001db9'
common = ['docker','run','--rm','--cpus=2','--memory=4g','--user',str(os.getuid())+':'+str(os.getgid()),
          '-v',str(root/'wine-src')+':/src:ro','-v',str(root/'wine-obj')+':/build',
          '-v',str(root/'fixture')+':/fixture','-w','/build',
          '-e','HOME=/build/home','-e','XDG_CACHE_HOME=/build/cache']

def input_hashes():
    sources = json.loads((root/'runtime-source-verification.json').read_text())['source_hashes']
    paths = [root/'wine-src'/name for name in sources]
    paths += [root/'wine-src/loader/tests'/name for name in
              ['a1b-live-private-view-pe.c','a1b-live-private-view-helper.c','a1b-live-private-view-unix.c','a1b-live-private-view-inject.c']]
    paths += [root/'wine-obj'/name for name in
              ['config.status','loader/wine','loader/wine-preloader','server/wineserver','dlls/ntdll/ntdll.so',
               'dlls/ntdll/x86_64-windows/ntdll.dll','dlls/ntdll/tests/x86_64-windows/ntdll_test.exe']]
    paths += [root/'proof-runner.py', root/'wine-src/loader/tests/a1b-live-private-view-run.py']
    paths += [root/'fixture'/name for name in
              ['a1b-live-private-view-pe.exe','executor/a1b-live-private-view-pe.exe',
               'x86_64-windows/a1b-live-private-view-helper.dll','x86_64-unix/a1b-live-private-view-helper.so',
               'a1b-live-private-view-inject.so']]
    return {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths if p.is_file()}

def cancellation_trace_contracts(name, controls):
    events = []
    for line in (root/(name+'.log')).read_text(errors='replace').splitlines():
        match = re.search(r'(private-apc|private-lease) (event=.*)', line)
        if match:
            fields = dict(re.findall(r'(\w+)=(\S+)', match[2]))
            fields['kind'] = match[1]; events.append(fields)
    evidence = []; errors = []
    expected = 1 if name.startswith(('cancel-map','cancel-revoke')) else 2
    if len(controls) != expected: errors.append('missing authoritative recipient termination controls')
    for control in controls:
        queued = control['queued']; identifier = queued['id']; op = control['op']
        matching = [(i,e) for i,e in enumerate(events) if e['kind'] == 'private-apc' and e.get('id') == identifier]
        cancelled = next(((i,e) for i,e in matching if e.get('event') == 'cancelled'), None)
        if not cancelled or cancelled[1].get('detail') != 'thread_queue_cleared':
            errors.append(op+': missing real thread queue cancellation'); continue
        if any(e.get('event') in ('dequeued','delivered','completed') for _,e in matching):
            errors.append(op+': cancelled original APC reached dequeue/delivery/completion')
        cancel_index = cancelled[0]
        lease_events = [(i,e) for i,e in enumerate(events) if e['kind'] == 'private-lease' and
                        e.get('lease') == queued['lease'] and e.get('generation') == queued['generation'] and
                        e.get('consumer_pid') == queued['recipient_pid']]
        if not any(i > cancel_index and e.get('event') == 'apc_count' and e.get('apc_count') == '0' for i,e in lease_events):
            errors.append(op+': cancelled APC count did not drain')
        result = {'op':op, 'cancelled_id':identifier, 'recipient_tid':queued['recipient_tid']}
        if op == 'MAP':
            if not any(i > cancel_index and e.get('event') == 'revoked' and e.get('status') == 'c0000120' for i,e in lease_events):
                errors.append('MAP: cancelled lease missing STATUS_CANCELLED')
        else:
            retry = next(((i,e) for i,e in enumerate(events) if i > cancel_index and e['kind'] == 'private-apc' and
                          e.get('event') == 'queued' and e.get('op') == 'REVOKE' and e.get('lease') == queued['lease'] and
                          e.get('recipient_pid') == queued['recipient_pid'] and e.get('recipient_tid') != queued['recipient_tid']), None)
            ack = next(((i,e) for i,e in lease_events if i > cancel_index and e.get('event') == 'ack'), None)
            if not retry or not ack: errors.append('REVOKE: missing survivor retry or real client ACK')
            else:
                retry_index, retry_event = retry; ack_index = ack[0]
                retry_events = [(i,e) for i,e in enumerate(events) if e['kind'] == 'private-apc' and e.get('id') == retry_event['id']]
                if not any(retry_index < i < ack_index and e.get('event') == 'delivered' for i,e in retry_events):
                    errors.append('REVOKE: native ACK did not follow survivor delivery')
                if not any(e.get('event') == 'completed' and e.get('result_type') == '16' for _,e in retry_events):
                    errors.append('REVOKE: survivor APC result did not finish')
                if any(cancel_index < i < ack_index and e.get('event') in ('ready','revoked') for i,e in lease_events):
                    errors.append('REVOKE: cancellation falsely completed revoke before native ACK')
                result.update(retry_id=retry_event['id'], survivor_tid=retry_event['recipient_tid'], ack_sequence=ack[1]['seq'])
        evidence.append(result)
    return {'passed':not errors, 'evidence':evidence, 'errors':errors}

def execute(name, argv):
    before = input_hashes()
    (root/(name+'-command.json')).write_text(json.dumps({'argv':argv},indent=2)+'\n')
    start = datetime.datetime.now(datetime.timezone.utc).isoformat()
    controls = []
    with (root/(name+'.log')).open('w') as log:
        p = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT)
        if name.startswith('cancel-'):
            armed = {}; queued = {}; seen = []; position = 0; killed = set()
            directory = root/'fixture'/('gate-'+name)
            while p.poll() is None:
                with (root/(name+'.log')).open() as trace:
                    trace.seek(position)
                    data = trace.read()
                    boundary = data.rfind('\n') + 1
                    lines = data[:boundary].splitlines()
                    position += boundary
                for line in lines:
                    if 'private-apc ' in line: seen.append(line.strip())
                    match = re.search(r'cancellation-armed op=(MAP|REVOKE) recipient_pid=([0-9a-f]+) recipient_tid=([0-9a-f]+)', line)
                    if match: armed[match[1]] = (int(match[2],16), int(match[3],16))
                    if 'private-apc event=queued ' in line:
                        fields = dict(re.findall(r'(\w+)=(\S+)', line))
                        if fields.get('op') in ('MAP','REVOKE'):
                            queued.setdefault(fields['op'], []).append(fields)
                for op in ('MAP', 'REVOKE'):
                    identity = directory/('armed-'+op.lower())
                    if identity.exists():
                        fields = identity.read_text().split()
                        if len(fields) == 2: armed[op] = tuple(int(field,16) for field in fields)
                for op, expected in armed.items():
                    if op in killed: continue
                    selected = next((f for f in queued.get(op, [])
                                     if (int(f['recipient_pid'],16), int(f['recipient_tid'],16)) == expected), None)
                    phase = op.lower()
                    if not selected or not (directory/('parked-'+phase)).exists(): continue
                    if any('event=dequeued ' in event and 'id='+selected['id']+' ' in event for event in seen):
                        raise RuntimeError('Cancellation APC already dequeued; refuse invalid recipient kill')
                    (directory/('queued-'+phase)).touch()
                    if op == 'REVOKE' and not (directory/('verified-'+phase)).exists(): continue
                    controls.append({'op':op, 'queued':selected, 'action':'authorize-real-recipient-termination'})
                    (directory/('kill-'+phase)).touch(); killed.add(op)
                time.sleep(0.005)
        p.wait()
    if controls:
        (root/(name+'-controls.json')).write_text(json.dumps(controls,indent=2)+'\n')
    after = input_hashes()
    stable = before == after
    invalid = 'Test inputs changed during the run; evidence invalid' if sys.argv[1] in ('run','vm') and not stable else None
    contract = cancellation_trace_contracts(name, controls) if name.startswith('cancel-') else None
    if contract and not contract['passed']:
        invalid = 'Cancellation trace contract failed: '+ '; '.join(contract['errors'])
    digest = hashlib.sha256((root/(name+'.log')).read_bytes()).hexdigest()
    (root/(name+'-result.json')).write_text(json.dumps({'exit':p.returncode,'evidence_invalid_reason':invalid,'trace_contract':contract,'input_sha256_before':before,'input_sha256_after':after,'start':start,'end':datetime.datetime.now(datetime.timezone.utc).isoformat(),'log_sha256':digest},indent=2)+'\n')
    print(name, 'exit',p.returncode, 'log',root/(name+'.log'),flush=True)
    print('\n'.join((root/(name+'.log')).read_text(errors='replace').splitlines()[-20:]),flush=True)
    return 1 if invalid else p.returncode

if sys.argv[1] == 'runtime-build':
    sys.exit(execute('runtime-build',common+[sdk,'bash','-lc','make -j1 V=1 dlls/ntdll/ntdll.so']))
if sys.argv[1] == 'vm':
    name = sys.argv[2]
    env = ['-e','WINEARCH=win64','-e','WINEPREFIX=/fixture/prefix-'+name,
           '-e','WINEDLLOVERRIDES=mscoree,mshtml=','-e','WINEDEBUG=-all']
    tree = '/build'
    if name == 'vm-on':
        env += ['-e','WINE_SHARED_PRIVATE_BACKING=1']
    if name == 'vm-baseline':
        env += ['-v',os.environ['A1B_BASELINE_OBJECTS']+':/baseline:ro']
        tree = '/baseline'
    cmd = 'timeout --kill-after=15s 240s xvfb-run -a /src/tools/runtest -v -T '+tree+' -M ntdll.dll -p /build/dlls/ntdll/tests/x86_64-windows/ntdll_test.exe virtual\nfixture_status=$?\n'+tree+'/server/wineserver -k\nexit "$fixture_status"'
    sys.exit(execute(name,common+env+[sdk,'bash','-lc',cmd]))
if sys.argv[1] == 'build':
    cmd = '''mkdir -p /fixture/x86_64-windows /fixture/x86_64-unix &&
gcc -shared -fPIC -Wall -Wextra -o /fixture/a1b-live-private-view-inject.so /src/loader/tests/a1b-live-private-view-inject.c &&
gcc -shared -fPIC -Wall -Wextra -D__WINESRC__ -I/src/include -I/build/include -o /fixture/x86_64-unix/a1b-live-private-view-helper.so /src/loader/tests/a1b-live-private-view-unix.c &&
tools/winegcc/winegcc -shared -o /fixture/x86_64-windows/a1b-live-private-view-helper.dll --wine-objdir /build -b x86_64-w64-mingw32 -D_MSVCR_VER=0 -D__WINESRC__ -I/src/include -I/src/include/msvcrt -I/build/include -Wl,--entry,DllMain -Wl,--wine-builtin /src/loader/tests/a1b-live-private-view-helper.c -lntdll -lkernel32 &&
tools/winegcc/winegcc -o /fixture/a1b-live-private-view-pe.exe --wine-objdir /build -b x86_64-w64-mingw32 -mconsole -Wall -Wextra -D_MSVCR_VER=0 -D__WINESRC__ -I/src/include -I/src/include/msvcrt -I/build/include -Wl,--large-address-aware /src/loader/tests/a1b-live-private-view-pe.c -lmsvcrt -lntdll -lkernel32 &&
mkdir -p /fixture/executor &&
tools/winegcc/winegcc -o /fixture/executor/a1b-live-private-view-pe.exe --wine-objdir /build -b x86_64-w64-mingw32 -mconsole -Wall -Wextra -D_MSVCR_VER=0 -D__WINESRC__ -I/src/include -I/src/include/msvcrt -I/build/include -Wl,--large-address-aware -Wl,--image-base,0x400002000000 -Wl,--disable-dynamicbase /src/loader/tests/a1b-live-private-view-pe.c -lmsvcrt -lntdll -lkernel32'''
    sys.exit(execute('fixture-build-'+datetime.datetime.now(datetime.timezone.utc).strftime('%H%M%S'),common+[sdk,'bash','-lc',cmd]))
if sys.argv[1] == 'run':
    name = sys.argv[2]
    debug = sys.argv[3] if len(sys.argv)>3 else '-all'
    env = ['-e','WINEARCH=win64','-e','WINEPREFIX=/fixture/prefix-'+name,
           '-e','WINEDLLOVERRIDES=mscoree,mshtml=','-e','WINEDEBUG='+debug,'-e','A1B_VERBOSE_CHECKS=1',
           '-e','WINEDLLPATH=/fixture','-e','A1B_VIEW_GATE_DIR=/fixture/gate-'+name,
           '-e','LD_PRELOAD=/fixture/a1b-live-private-view-inject.so',
           '-e','WINE_PRIVATE_MAPPING_TRACE=1']
    extra = ''
    if name.startswith('cancel-'):
        extra = ' --cancel-revoke' if name.startswith('cancel-revoke') else (' --cancel-map' if name.startswith('cancel-map') else ' --cancel-queued')
    if name.startswith('backing-off'):
        env += ['-e','A1B_DISABLE_BACKING=1']
        extra = ' --backing-off'
    cmd = '''mkdir -p "$A1B_VIEW_GATE_DIR" && timeout --kill-after=5s 180s xvfb-run -a /build/loader/wine /fixture/a1b-live-private-view-pe.exe
fixture_status=$?
/build/server/wineserver -k
/build/server/wineserver -w
exit "$fixture_status"'''
    cmd = cmd.replace('/fixture/a1b-live-private-view-pe.exe\n', '/fixture/a1b-live-private-view-pe.exe'+extra+'\n')
    sys.exit(execute(name,common+env+[sdk,'bash','-lc',cmd]))

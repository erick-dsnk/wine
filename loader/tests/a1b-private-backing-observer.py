#!/usr/bin/env python3
# Benign Linux /proc observer for actual private-backing lifetime.
# SPDX-License-Identifier: LGPL-2.1-or-later
# Run inside the documented SDK with /src, /build and /matrix mounts.
import hashlib,json,os,pathlib,re,subprocess,sys,time
out=pathlib.Path(os.environ.get('A1B_EVIDENCE_DIRECTORY','/matrix'))
mode=sys.argv[1]
base=None
snapshots=[]
initial={}
errors=[]
def fd_inventory(pid):
    entries=[]
    for fd in pathlib.Path('/proc',str(pid),'fd').glob('*'):
        try:
            st=fd.stat()
            entries.append({'fd':int(fd.name),'inode':st.st_ino,'device':st.st_dev,'link':os.readlink(fd)})
        except FileNotFoundError: pass
    return entries

def wine_processes():
    found=[]
    for proc in pathlib.Path('/proc').iterdir():
        if not proc.name.isdigit(): continue
        try: cmd=(proc/'cmdline').read_bytes().replace(b'\x00',b' ').decode(errors='replace')
        except (PermissionError,FileNotFoundError,ProcessLookupError): continue
        if 'ntdll_test.exe' in cmd or '/build/server/wineserver' in cmd:
            found.append((int(proc.name),cmd))
    return found

def snapshot(stage):
    fixture=[]
    servers=[]
    for pid,cmd in wine_processes():
        if '/build/server/wineserver' in cmd:
            servers.append({'pid':pid,'command':cmd,'fds':fd_inventory(pid)})
            continue
        try:
            maps=pathlib.Path('/proc',str(pid),'maps').read_text()
            selected=None
            for line in maps.splitlines():
                cols=line.split()
                start,end=[int(x,16) for x in cols[0].split('-')]
                if start <= base < end:
                    major,minor=[int(x,16) for x in cols[3].split(':')]
                    selected={'line':line,'permissions':cols[1],'inode':int(cols[4]),'device':cols[3],'stat_device':os.makedev(major,minor)}
                    break
            if not selected or selected['permissions'][0] != 'r': continue
            executable=os.readlink('/proc/'+str(pid)+'/exe')
            if 'wine' not in pathlib.Path(executable).name: continue
            role='child' if 'vm-backing-child' in cmd else 'parent'
            fixture.append({'pid':pid,'command':cmd,'executable':executable,'role':role,'mapping':selected,'fds':fd_inventory(pid),'maps':maps})
        except (FileNotFoundError,ProcessLookupError): continue
    result={'stage':stage,'fixture':fixture,'servers':servers}
    snapshots.append(result)
    print(json.dumps({'stage':stage,'fixture':[{k:v for k,v in x.items() if k not in ['fds','maps']} for x in fixture], 'server_pids':[x['pid'] for x in servers]}),flush=True)
    return result

def require(condition,description):
    if not condition: errors.append(description);print('observer FAIL '+description,flush=True)

if mode == 'create':
    pathlib.Path(os.environ['WINEPREFIX']).mkdir(parents=True,exist_ok=True)
    server_log=out/'observer-create-server-v2.log'
    server_output=server_log.open('w')
    subprocess.run(['/build/server/wineserver','-p'],stdout=server_output,stderr=subprocess.STDOUT,check=True)
    client_log=out/'observer-create-client.log'
    with client_log.open('w') as client_output:
        run=subprocess.run(['/build/wine','/build/a1b-private-backing-matrix.exe','--injected-create'],stdout=client_output,stderr=subprocess.STDOUT,text=True)
    print(client_log.read_text(),flush=True)
    require(run.returncode==0,'injected creation fixture exits zero')
    server_text=server_log.read_text()
    print(server_text,flush=True)
    hits=re.findall(r'private-backing-create-fail: hit pid=(\d+) fd=(\d+) offset=0x39000 left=(\d+) inode=(\d+) device=(\d+) inspected=1',server_text)
    require(len(hits)==2,'both intended server backing candidates fail exactly once')
    inspected=[]
    for pid,fd,left,inode,device in hits:
        fds=fd_inventory(int(pid))
        inspected.append({'server_pid':int(pid),'failed_fd':int(fd),'failed_inode':int(inode),'failed_device':int(device),'remaining_fds':fds})
        require((int(device),int(inode)) not in {(item['device'],item['inode']) for item in fds},'failed backing inode has no retained server FD')
    subprocess.run(['/build/server/wineserver','-k'],check=True)
    subprocess.run(['/build/server/wineserver','-w'],check=True)
    server_output.close()
    result={'mode':mode,'runner_exit':run.returncode,'hits':hits,'server_log':server_text,'failures':errors,'after_creation':inspected}
    (out/'observer-create-snapshots.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'mode':mode,'failures':errors,'hits':len(hits)}),flush=True)
    sys.exit(bool(errors))

pathlib.Path(os.environ['WINEPREFIX']).mkdir(parents=True,exist_ok=True)
subprocess.run(['/build/server/wineserver','-p'],check=True)
argv=['xvfb-run','-a','/src/tools/runtest','-v','-T','/build','-M','ntdll.dll','-p','/build/dlls/ntdll/tests/x86_64-windows/ntdll_test.exe','virtual']
proc=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,bufsize=1)
lines=[]
for line in proc.stdout:
    lines.append(line)
    print(line,end='',flush=True)
    # Persistent Wine services may inherit the output pipe. The complete
    # test summary and the runner's real exit status delimit this fixture.
    if re.search(r':virtual: [1-9][0-9]* tests executed',line): break
    if 'shared_private_backing_probe state=resident' in line:
        match=re.search(r'base=(?:0x)?([0-9a-fA-F]+) size=',line)
        require(bool(match),'parse observed real fixture address')
        if not match: continue
        base=int(match.group(1),16)
        snap=snapshot('resident')
        require(len(snap['fixture'])==2,'two actual same-VA fixture processes resident')
        require(sorted(x['role'] for x in snap['fixture'])==['child','parent'],'actual Wine fixture parent and child identified')
        require(len(snap['servers'])==1,'one persistent server observed')
        if len(snap['fixture'])==2:
            initial.update({x['role']:x for x in snap['fixture']})
            if mode=='on':
                require(all(x['mapping']['inode'] for x in snap['fixture']),'both private mappings have backing inodes')
                require(len({x['mapping']['inode'] for x in snap['fixture']})==2,'separate target mappings use distinct backing inodes')
                server_inodes={(fd['device'],fd['inode']) for s in snap['servers'] for fd in s['fds']}
                require(all((x['mapping']['stat_device'],x['mapping']['inode']) in server_inodes for x in snap['fixture']),'server owns both live backing FDs')
            else:
                require(all(x['mapping']['inode']==0 for x in snap['fixture']),'default-off real allocations have no file backing')
    elif 'shared_private_backing_probe state=free owner=child' in line and initial:
        snap=snapshot('child-exit')
        require(len(snap['fixture'])==1,'child exits while parent allocation remains resident')
        if len(snap['fixture'])==1:
            require(snap['fixture'][0]['pid']==initial['parent']['pid'],'remaining mapping belongs to original parent')
            require(snap['fixture'][0]['role']=='parent','parent allocation remains in its native process')
        require(not pathlib.Path('/proc',str(initial['child']['pid'])).exists(),'child native process has exited')
        if mode=='on':
            fds={(fd['device'],fd['inode']) for s in snap['servers'] for fd in s['fds']}
            require((initial['child']['mapping']['stat_device'],initial['child']['mapping']['inode']) not in fds,'server closes exited child backing FD')
            require((initial['parent']['mapping']['stat_device'],initial['parent']['mapping']['inode']) in fds,'server preserves parent backing FD until parent releases')
status=proc.wait()
print('fixture runner exit',status,flush=True)
require(status==0,'complete virtual suite exits zero')
require(len(snapshots)==2,'both requested fixture snapshots observed')
if base is not None:
    snap=snapshot('complete')
    require(not snap['fixture'],'test fixture processes disposed after suite')
    if mode=='on' and initial:
        fds={(fd['device'],fd['inode']) for s in snap['servers'] for fd in s['fds']}
        require(all((x['mapping']['stat_device'],x['mapping']['inode']) not in fds for x in initial.values()),'server closes both observed backing FDs after release/exit')
subprocess.run(['/build/server/wineserver','-k'],check=True)
subprocess.run(['/build/server/wineserver','-w'],check=True)
result={'mode':mode,'runner_exit':status,'failures':errors,'snapshots':snapshots,'byte_observation':'Direct bytes are asserted by the Wine fixture; /proc/mem is not read by this observer.'}
(out/('observer-'+mode+'-snapshots.json')).write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'mode':mode,'failures':errors,'snapshots':len(snapshots)}),flush=True)
sys.exit(bool(errors))

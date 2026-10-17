#!/usr/bin/env python3
"""Local regression gate; does not claim an SDK build or physical-board validation."""
import argparse,ast,importlib.util,json,os,platform,shutil,subprocess,sys,tempfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--report',type=Path,default=ROOT/'validation/host_checks.json');a=ap.parse_args()
    results=[]
    def run(name,cmd):
        start=time.monotonic();proc=subprocess.run(cmd,cwd=ROOT,capture_output=True,text=True)
        results.append({'name':name,'pass':proc.returncode==0,'exit_code':proc.returncode,'seconds':round(time.monotonic()-start,3),'output':(proc.stdout+proc.stderr).strip()})
        print(('PASS' if proc.returncode==0 else 'FAIL')+': '+name,flush=True)
        if proc.returncode:print((proc.stdout+proc.stderr)[-6000:])
        return proc.returncode==0
    try:
        for p in ROOT.rglob('*.py'):
            if not any(x in p.parts for x in ['.venv','node_modules','legacy']):ast.parse(p.read_text(),filename=str(p.relative_to(ROOT)))
        results.append({'name':'Python syntax','pass':True})
    except (SyntaxError,UnicodeError) as e:results.append({'name':'Python syntax','pass':False,'output':str(e)})
    run('Python lifecycle, evidence and measurement tests',[sys.executable,'-m','unittest','discover','-s','tests','-p','test_tools.py','-v'])
    if all(importlib.util.find_spec(x) for x in ['fastapi','httpx','dotenv','requests']):
        run('Dashboard API and built frontend (offline)',[sys.executable,'-m','unittest','discover','-s','tests','-p','test_dashboard.py','-v'])
    else:
        results.append({'name':'Dashboard API tests','pass':True,'skipped':True,'output':'Install requirements-dev.txt to run optional API tests'})
    cc=shutil.which('gcc') or shutil.which('cc')
    if not cc:results.append({'name':'Native checks','pass':False,'output':'Install a C compiler: GCC/Clang'})
    else:
        with tempfile.TemporaryDirectory(prefix='pqc-check-',dir=ROOT) as temp:
            out=Path(temp);inc=ROOT/'sender/sender/include'
            jobs=[('CoAP and wire format',['tests/test_coap.c','common/coap_minimal.c'],[]),('State transitions',['tests/test_state.c'],[]),('RNG and KEM',['tests/test_rng_kem.c','sender/sender/pqkem_kem.c'],['-Itests/stubs','-Isender/sender/kyber/kyber512_ref'])]
            for i,(name,files,extra) in enumerate(jobs):
                binary=out/f'check_{i}';cmd=[cc,'-std=c99','-O2','-Wall','-Wextra','-Icommon','-I'+str(inc),*extra,*files,'-o',str(binary)]
                if run(name+' compilation',cmd):run(name,[str(binary)])
    cxx=shutil.which('g++') or shutil.which('c++')
    if not cxx:results.append({'name':'Firmware storage tests','pass':False,'output':'Install a C++ compiler'})
    else:
        with tempfile.TemporaryDirectory(prefix='pqc-storage-',dir=ROOT) as temp:
            for role in ['sender','receiver']:
                folder='Receiver' if role=='receiver' else 'sender'
                binary=Path(temp)/role
                cmd=[cxx,'-std=c++11','-O1','-ffunction-sections','-fdata-sections','-Itests/stubs',f'-I{folder}/{folder}/include',f'-I{folder}/{folder}',f'tests/test_{role}_storage.cpp','-Wl,--gc-sections','-o',str(binary)]
                if run(role+' firmware syntax/storage compilation (test stubs)',cmd):run(role+' actual storage functions (simulated flash)',[str(binary)])
    report={'schema':1,'created_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'python':platform.python_version(),'platform':platform.system(),'passed':all(x['pass'] for x in results),'checks':results,'not_run':['BL602 SDK cross compilation/link','physical flashing, Wi-Fi and EasyFlash power-loss behavior','target entropy quality and cryptographic conformance vectors','physical security measurements'],'scope':'Local software regression tests. Test RNG is a fixture; not firmware randomness.'}
    a.report.parent.mkdir(parents=True,exist_ok=True);a.report.write_text(json.dumps(report,indent=2)+'\n');print('Report: '+str(a.report))
    return 0 if report['passed'] else 1
if __name__=='__main__':raise SystemExit(main())

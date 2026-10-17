#!/usr/bin/env python3
"""Build current PQC or legacy DTLS firmware. No shell evaluation of .env values."""
import argparse,ipaddress,json,os,re,shutil,subprocess,sys
from pathlib import Path
from project_config import read_env,c_string,atomic_write
ROOT=Path(__file__).resolve().parents[1]
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--profile',choices=['pqc','dtls'],default='pqc')
    ap.add_argument('--role',choices=['sender','receiver','Receiver','sniffer']);ap.add_argument('--all',action='store_true');ap.add_argument('--clean',action='store_true')
    ap.add_argument('--env-file',type=Path,default=Path(os.getenv('PQC_ENV_FILE',ROOT/'.env')))
    ap.add_argument('--receiver-port',help='DTLS: force fresh serial IP detection, even when an old address is configured')
    a=ap.parse_args()
    try:
        if a.all==bool(a.role):raise ValueError('choose either --role or --all')
        cfg=read_env(a.env_file);cfg.update({k:v for k,v in os.environ.items() if k in cfg or k in ['BL60X_SDK_PATH','WIFI_SSID','WIFI_PW','MAX_MAKE_JOBS']})
        for key in ['BL60X_SDK_PATH','WIFI_SSID','WIFI_PW']:
            if not cfg.get(key) or cfg[key].startswith(('YOUR_','/absolute/')):raise ValueError('configure '+key+' in .env')
        sdk=Path(cfg['BL60X_SDK_PATH']).expanduser().resolve()
        if not (sdk/'make_scripts_riscv/project.mk').is_file():raise ValueError('BL60X_SDK_PATH is not a compatible BL602 IoT SDK')
        if any(c.isspace() for c in str(ROOT)+str(sdk)):raise ValueError('SDK and project paths must not contain whitespace (legacy Makefiles)')
        jobs=cfg.get('MAX_MAKE_JOBS','2')
        if not jobs.isdecimal() or not 1<=int(jobs)<=64:raise ValueError('MAX_MAKE_JOBS must be 1..64')
        roles=['receiver','sender'] if a.all else [a.role.lower()]
        if a.profile=='dtls' and 'sniffer' in roles:raise ValueError('DTLS has no sniffer role')
        if a.profile=='dtls' and 'sender' in roles:
            host=cfg.get('DTLS_SERVER_HOST','auto')
            if a.receiver_port or host in ('','auto'):
                port=a.receiver_port or cfg.get('DTLS_RECEIVER_PORT')
                if not port:raise ValueError('set DTLS_SERVER_HOST to receiver IPv4 or pass --receiver-port')
                host=subprocess.check_output([
                    sys.executable,
                    str(ROOT/'host-tools/update_receiver_ip_from_serial.py'),
                    '--port', port,
                    '--baud', cfg.get('SERIAL_BAUDRATE', '921600'),
                    '--env-file', str(a.env_file),
                    '--quiet'
                ], text=True).strip()
            cfg['DTLS_SERVER_HOST']=str(ipaddress.IPv4Address(host))
        experiment=cfg.get('PQC_EXPERIMENT_ID','lab-unset')
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}',experiment):raise ValueError('PQC_EXPERIMENT_ID: use 1..64 letters, digits, dot, underscore or hyphen')
        for role in roles:
            name=('dtls_'+role) if a.profile=='dtls' else ('Receiver' if role=='receiver' else role)
            project=ROOT/'experiments/dtls_baseline'/name if a.profile=='dtls' else ROOT/name
            if a.profile=='pqc' and role=='sender':
                auth=(project/name/'include/sender_auth_key.h').read_text()
                if not re.search(r'PQC_CREDENTIAL_GENERATION\s+[1-9][0-9]*u',auth):raise ValueError('provision sender identity before building')
                prof=(project/name/'include/security_profile.h').read_text()
                fp=re.search(r'kProvisionedGatewayPkFingerprint.*?=\s*\{(.*?)\}',prof,re.S)
                if not fp or not any(int(h,16) for h in re.findall(r'0x([a-fA-F0-9]{2})',fp[1])):raise ValueError('pin receiver fingerprint before building sender')
            definitions=['#ifndef PQC_LOCAL_BUILD_CONFIG_H','#define PQC_LOCAL_BUILD_CONFIG_H']
            for key in ['WIFI_SSID','WIFI_PW']:
                definitions.append('#define '+key+' '+c_string(cfg[key]))
            definitions.append('#define PQC_EXPERIMENT_ID '+c_string(experiment))
            if a.profile=='pqc':
                oled=cfg.get('PQC_ENABLE_OLED','0')
                if oled not in ('0','1'):raise ValueError('PQC_ENABLE_OLED must be 0 or 1')
                definitions.append('#define PQC_ENABLE_OLED '+oled)
            elif role=='sender':definitions.append('#define DTLS_SERVER_HOST '+c_string(cfg['DTLS_SERVER_HOST']))
            if a.profile=='dtls':
                for key in ['DTLS_SAMPLE_COUNT','DTLS_REPEAT_SESSIONS','DTLS_INTER_MESSAGE_DELAY_MS']:
                    if key in cfg:
                        if not cfg[key].isdecimal():raise ValueError(key+' must be unsigned numeric')
                        definitions.append('#define '+key+' '+cfg[key]+'u')
            definitions.append('#endif')
            header=project/name/'include/build_config.h';atomic_write(header,'\n'.join(definitions)+'\n')
            link=sdk/'customer_app'/name;link.parent.mkdir(parents=True,exist_ok=True)
            if link.exists() or link.is_symlink():
                if link.resolve()!=project.resolve():raise ValueError(f'{link} already points elsewhere; use a separate SDK checkout')
            else:link.symlink_to(project,target_is_directory=True)
            if a.clean and (project/'build_out').exists():shutil.rmtree(project/'build_out')
            env=dict(os.environ,BL60X_SDK_PATH=str(sdk),MAX_MAKE_JOBS=jobs)
            env['DTLS_EXTRA_CFLAGS' if a.profile=='dtls' else 'PQC_EXTRA_CFLAGS']='-include '+str(header)
            print('Building '+name+' with generated local config',flush=True)
            subprocess.run(['sh','./genromap'],cwd=project,env=env,check=True)
            binary=project/'build_out'/f'{name}.bin'
            if not binary.exists():raise ValueError(f'Build returned but expected image missing: {binary}; inspect SDK output')
            print('Image: '+str(binary))
        return 0
    except (ValueError,OSError,subprocess.CalledProcessError) as e:print(f'ERROR: {e}',file=sys.stderr);return 2
if __name__=='__main__':raise SystemExit(main())

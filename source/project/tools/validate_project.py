#!/usr/bin/env python3
"""Check source consistency; --release checks unprovisioned packaging."""
import argparse,ast,hashlib,json,re,shutil,subprocess,sys
import xml.etree.ElementTree as ET
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SKIP={'.venv','node_modules','build_out','__pycache__','legacy'}
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--release',action='store_true');ap.add_argument('--manifest',action='store_true',help='Check pristine package hashes before provisioning/running tests');a=ap.parse_args();errors=[]
    for p in ROOT.rglob('*'):
        if not p.is_file() or any(x in SKIP or x.startswith(('pip-','pqc-check-','pqc-storage-')) for x in p.relative_to(ROOT).parts):continue
        try:
            if p.suffix=='.py':ast.parse(p.read_text())
            elif p.suffix=='.json':json.loads(p.read_text())
            elif p.suffix=='.xml':ET.parse(p)
            elif p.suffix=='.sh' and shutil.which('bash'):subprocess.run(['bash','-n',str(p)],check=True,capture_output=True)
        except Exception as e:errors.append(f'{p.relative_to(ROOT)}: {e}')
    profiles=[(ROOT/role/role/'include/security_profile.h').read_text() for role in ('sender','Receiver')]
    for value in ['PQC_PROTOCOL_VERSION 3u','PQC_SECURITY_PROFILE_VERSION 4u','PQC_AEAD_KEY_LEN 32u','PQC_DEVICE_AUTH_TAG_LEN 32u','PQC_HKDF_INFO "PQC-IOT-MLKEM512-AES256-CCM-v4"']:
        if not all('#define '+value in s for s in profiles):errors.append('Endpoint profile mismatch: '+value)
    if not (ROOT/'RUN_STEPS.md').is_file():errors.append('RUN_STEPS.md missing')
    if a.release:
        for p in ROOT.rglob('*'):
            if p.name in {'.env','build_config.h','node_modules','__pycache__'} or p.suffix in {'.pyc','.o','.elf','.bin'}:errors.append('Local artifact in release: '+str(p.relative_to(ROOT)))
        if (ROOT/'pi2_trust_authority/state/device_registry.json').exists():errors.append('Private device registry must not be packaged')
        auth=(ROOT/'sender/sender/include/sender_auth_key.h').read_text()
        if not re.search(r'PQC_CREDENTIAL_GENERATION\s+0u',auth):errors.append('Release sender is already provisioned')
        registry=(ROOT/'Receiver/Receiver/include/sender_auth_registry.h').read_text()
        if registry.count('0u, 0u, {0}')!=2:errors.append('Release receiver must contain two disabled zero-key slots')
    if a.manifest:
        manifest=ROOT/'FILE_MANIFEST.sha256'
        if not manifest.exists():errors.append('Checksum manifest missing')
        else:
            for line in manifest.read_text().splitlines():
                try:
                    expected,relative=line.split('  ',1);p=(ROOT/relative).resolve()
                    if not p.is_relative_to(ROOT) or p==manifest or not re.fullmatch(r'[0-9a-f]{64}',expected):raise ValueError('invalid manifest entry')
                    if hashlib.sha256(p.read_bytes()).hexdigest()!=expected:errors.append('Changed file: '+relative)
                except (ValueError,OSError) as e:errors.append(str(e))
    for error in errors:print('FAIL: '+error)
    print('Source/package validation '+('FAILED' if errors else 'PASSED')+'. Hardware build is a separate gate.')
    return 1 if errors else 0
if __name__=='__main__':raise SystemExit(main())

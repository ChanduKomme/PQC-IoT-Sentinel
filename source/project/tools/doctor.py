#!/usr/bin/env python3
"""Read-only checks of host tools and optional BL602 build configuration."""
import argparse
import importlib.util
import json
import os
import shutil
import sys
from pathlib import Path
from project_config import read_env

ROOT = Path(__file__).resolve().parents[1]

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--hardware', action='store_true')
    ap.add_argument('--env-file', type=Path, default=ROOT/'.env')
    args = ap.parse_args()
    checks = {'Python >= 3.10': sys.version_info >= (3,10),
              'C compiler': bool(shutil.which('gcc') or shutil.which('cc')),
              'C++ compiler': bool(shutil.which('g++') or shutil.which('c++'))}
    if args.hardware:
        try:
            config = read_env(args.env_file)
            sdk = Path(os.getenv('BL60X_SDK_PATH', config.get('BL60X_SDK_PATH','/missing'))).expanduser()
            checks.update({'BL602 SDK project.mk': (sdk/'make_scripts_riscv/project.mk').is_file(),
                           'Wi-Fi SSID configured': bool(config.get('WIFI_SSID')) and not config.get('WIFI_SSID','').startswith('YOUR_'),
                           'Wi-Fi password configured': bool(config.get('WIFI_PW')) and not config.get('WIFI_PW','').startswith('YOUR_'),
                           'pyserial installed': importlib.util.find_spec('serial') is not None,
                           'blflash on PATH': shutil.which('blflash') is not None})
        except ValueError as exc:
            print(f'ERROR: {exc}', file=sys.stderr)
            return 2
    for name, passed in checks.items():
        print(f'{"PASS" if passed else "MISSING"}: {name}')
    print('This check does not compile the SDK or detect/provision a physical board.')
    return 0 if all(checks.values()) else 1

if __name__ == '__main__':
    raise SystemExit(main())

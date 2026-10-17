#!/usr/bin/env python3
"""Verify and safely extract the public research bundles (standard library only)."""
import argparse
import hashlib
import json
import tarfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out', type=Path, default=ROOT / '.reproduce/raw')
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    target_root = args.out.resolve()
    count = 0
    for item in json.loads((ROOT / 'artifact/BUNDLES.json').read_text()):
        path = ROOT / item['path']
        assert hashlib.sha256(path.read_bytes()).hexdigest() == item['sha256'], path
        with tarfile.open(path) as tar:
            for member in tar.getmembers():
                name = PurePosixPath(member.name)
                if not member.isfile() or name.is_absolute() or '..' in name.parts:
                    raise ValueError('Unsafe archive entry: ' + member.name)
                out = target_root / member.name
                if not out.resolve().is_relative_to(target_root):
                    raise ValueError('Archive entry escapes output: ' + member.name)
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_bytes(tar.extractfile(member).read())
                count += 1
    print(f'PASS: verified and extracted {count} evidence files to {args.out}')

if __name__ == '__main__':
    main()

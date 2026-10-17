#!/usr/bin/env python3
"""Check every published file against artifact/SHA256SUMS.txt."""
import hashlib
from pathlib import Path, PurePosixPath

ROOT=Path(__file__).resolve().parents[1]
count=0
for line in (ROOT/'artifact/SHA256SUMS.txt').read_text().splitlines():
    digest,name=line.split('  ',1)
    rel=PurePosixPath(name)
    assert not rel.is_absolute() and '..' not in rel.parts,name
    path=ROOT/name
    assert path.is_file(),'Missing file: '+name
    assert hashlib.sha256(path.read_bytes()).hexdigest()==digest,'Hash mismatch: '+name
    count+=1
print(f'PASS: {count} published files match their SHA-256 hashes')

#!/usr/bin/env python3
"""Regenerate hashes after an intentional artifact change; review before committing."""
import hashlib
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
DEST=ROOT/'artifact/SHA256SUMS.txt'
EXCLUDED={'.git','.reproduce','__pycache__','.venv','node_modules','build_out'}
paths=sorted(p for p in ROOT.rglob('*') if p.is_file() and p!=DEST and not EXCLUDED.intersection(p.relative_to(ROOT).parts))
DEST.write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.relative_to(ROOT).as_posix()+'\n' for p in paths))
print('Recorded',len(paths),'file hashes')

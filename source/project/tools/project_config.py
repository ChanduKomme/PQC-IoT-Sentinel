"""Validated local configuration and atomic credential writes (standard library only)."""
import json, os, re, tempfile
from pathlib import Path

def atomic_write(path, text, private=True):
    path=Path(path); path.parent.mkdir(parents=True,exist_ok=True)
    fd,name=tempfile.mkstemp(prefix=path.name+'.',dir=path.parent)
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as out:
            out.write(text);out.flush();os.fsync(out.fileno())
        if private: os.chmod(name,0o600)
        os.replace(name,path)
    finally:
        if os.path.exists(name): os.unlink(name)

def uint32(v,name):
    if isinstance(v,bool) or not isinstance(v,int) or not 1<=v<=0xffffffff:
        raise ValueError(name+' must be an integer in 1..4294967295')
    return v

def validate_registry(data):
    if not isinstance(data,dict) or data.get('version')!=1 or not isinstance(data.get('devices'),list):
        raise ValueError('unsupported registry structure/version')
    if len(data['devices'])>2: raise ValueError('firmware supports two credential slots')
    slots=set();ids=set()
    for d in data['devices']:
        slot=d.get('slot')
        if type(slot) is not int or slot not in (1,2) or slot in slots: raise ValueError('slots must be unique: 1 or 2')
        sid=uint32(d.get('sender_id'),'sender_id');uint32(d.get('generation'),'generation')
        if sid in ids:raise ValueError('sender_id must be unique')
        if d.get('status') not in ('active','revoked'):raise ValueError('status must be active or revoked')
        key=d.get('auth_key_hex','')
        if not isinstance(key,str) or not re.fullmatch(r'[0-9a-fA-F]{64}',key) or int(key,16)==0:
            raise ValueError('credential must be a nonzero 32-byte hex key')
        if not isinstance(d.get('name'),str) or not d['name'].strip():raise ValueError('name is required')
        slots.add(slot);ids.add(sid)
    return data

def read_env(path):
    """Read KEY=value, optionally quoted, without shell expansion or execution."""
    out={}
    if not Path(path).exists():return out
    for n,line in enumerate(Path(path).read_text().splitlines(),1):
        line=line.strip()
        if not line or line.startswith('#'):continue
        m=re.fullmatch(r'([A-Z][A-Z0-9_]*)\s*=\s*(.*)',line)
        if not m:raise ValueError(f'invalid .env assignment on line {n}')
        key,value=m.groups()
        if len(value)>=2 and value[0]==value[-1] and value[0] in "\"'":value=value[1:-1]
        if key in out:raise ValueError(f'duplicate .env key: {key}')
        out[key]=value
    return out

def c_string(value):
    if any(ord(c)<32 or ord(c)==127 for c in value):raise ValueError('configuration values cannot contain control characters')
    # Octal escapes are fixed width and work in old embedded C/C++ compilers.
    return '"'+''.join(chr(b) if 32<=b<127 and chr(b) not in '\\"' else ('\\'+chr(b) if chr(b) in '\\"' else f'\\{b:03o}') for b in value.encode())+'"'

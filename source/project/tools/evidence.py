"""Exact structured event parsing. Host annotations never imply board acceptance."""
import csv,json,re
from pathlib import Path
FIELDS=('event_type','origin','role','device_id','experiment_id')
def parse_event(line):
    if '[EVENT] ' in line:line=line.split('[EVENT] ',1)[1]
    elif not line.lstrip().startswith('{'):return None
    try:obj=json.loads(line)
    except json.JSONDecodeError:raise ValueError('invalid JSON event line')
    if not isinstance(obj,dict) or any(not isinstance(obj.get(k),str) or not obj[k] for k in FIELDS):raise ValueError('missing event identity fields')
    if not re.fullmatch(r'[A-Z][A-Z0-9_]{0,63}',obj['event_type']):raise ValueError('invalid event_type')
    return obj
def read_events(path):
    path=Path(path)
    if path.suffix.lower()=='.csv':
        with path.open(newline='') as f:
            reader=csv.DictReader(f)
            if not set(FIELDS)<=set(reader.fieldnames or []):raise ValueError('CSV lacks structured event fields')
            return [parse_event(json.dumps(row)) for row in reader]
    out=[]
    for line in path.read_text().splitlines():
        row=parse_event(line)
        if row is not None:out.append(row)
    return out
def unique_events(events):
    seen=set();out=[]
    for event in events:
        key=event.get('event_id')
        if not key:raise ValueError('event_id missing; use tools/capture_serial.py or export event_id from Splunk')
        encoded=json.dumps(event,sort_keys=True)
        pair=(key,encoded)
        if key in seen:
            previous=next(x for x in out if x['event_id']==key)
            if previous!=event:raise ValueError('event_id collision with different content')
            continue
        seen.add(key);out.append(event)
    return out

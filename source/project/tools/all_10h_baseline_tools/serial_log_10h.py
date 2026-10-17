#!/usr/bin/env python3
from __future__ import annotations
import argparse, sys, time
from datetime import datetime, timezone
from pathlib import Path
import serial

def now(): return datetime.now(timezone.utc).isoformat(timespec='milliseconds')

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--port',required=True)
    ap.add_argument('--baud',type=int,default=2000000)
    ap.add_argument('--duration-hours',type=float,default=10.0)
    ap.add_argument('--output',required=True)
    ap.add_argument('--role',choices=('sender','receiver'),required=True)
    ap.add_argument('--profile',choices=('plain','classical','dtls','pqc'),required=True)
    a=ap.parse_args()
    out=Path(a.output); out.parent.mkdir(parents=True,exist_ok=True)
    start=time.monotonic(); duration=a.duration_hours*3600; lines=bytes_=0
    try: ser=serial.Serial(a.port,a.baud,timeout=1)
    except Exception as e:
        print(f'[ERROR] Cannot open {a.port}: {e}',file=sys.stderr); return 2
    with ser,out.open('w',encoding='utf-8',buffering=1) as f:
        h=f'# profile={a.profile} role={a.role} port={a.port} baud={a.baud} requested_duration_hours={a.duration_hours} start_utc={now()}'
        print(h); f.write(h+'\n')
        try:
            while time.monotonic()-start < duration:
                raw=ser.readline()
                if not raw: continue
                bytes_ += len(raw); text=raw.decode('utf-8',errors='replace').rstrip('\r\n')
                line=f'[{now()}] {text}'; print(line); f.write(line+'\n'); lines+=1
        except KeyboardInterrupt:
            print('\n[INFO] Logger stopped by user')
        tail=f'# end_utc={now()} lines={lines} bytes={bytes_} elapsed_seconds={time.monotonic()-start:.3f}'
        print(tail); f.write(tail+'\n')
    return 0
if __name__=='__main__': raise SystemExit(main())

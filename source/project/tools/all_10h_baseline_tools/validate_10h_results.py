#!/usr/bin/env python3
import argparse,csv,math
from pathlib import Path
def load(p):
 d={}
 with Path(p).open(newline='',encoding='utf-8') as f:
  for r in csv.DictReader(f):d[r['Metric']]=r['Value']
 return d
def num(v):
 try:return float(v)
 except:return math.nan
def main():
 ap=argparse.ArgumentParser();ap.add_argument('summaries',nargs='+');ap.add_argument('--minimum-hours',type=float,default=9.5);a=ap.parse_args();bad=False
 for p in a.summaries:
  d=load(p);h=num(d.get('Observed duration hours'));ok=num(d.get('Sender successful messages'));rate=num(d.get('Sender success rate percent'));print(f'{Path(p).name}: hours={h:.3f} sender_ok={ok:.0f} success={rate:.3f}%')
  if math.isnan(h) or h<a.minimum_hours:print('  [FAIL] duration below threshold');bad=True
  if math.isnan(ok) or ok<=0:print('  [FAIL] no successful sender messages');bad=True
  if math.isnan(rate):print('  [FAIL] success rate unavailable');bad=True
 raise SystemExit(1 if bad else 0)
if __name__=='__main__':main()

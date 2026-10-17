#!/usr/bin/env python3
import argparse,csv,math
from pathlib import Path

def load(p):
 d={}
 with Path(p).open(newline='',encoding='utf-8') as f:
  for r in csv.DictReader(f):d[r['Metric']]=r['Value']
 return d
def n(v):
 try:return float(v)
 except:return math.nan
def fmt(v,d=2):
 x=n(v); return '--' if math.isnan(x) else f'{x:.{d}f}'
def esc(s):return s.replace('&',r'\&').replace('_',r'\_').replace('%',r'\%')
def main():
 ap=argparse.ArgumentParser(); [ap.add_argument('--'+x,required=True) for x in ('plain','classical','dtls','pqc')]; ap.add_argument('--out-dir',required=True); a=ap.parse_args()
 names={'plain':'Plain CoAP','classical':'ECDH+HKDF+AES-CCM','dtls':'DTLS 1.2 AES-256-CCM','pqc':'ML-KEM+AES-256-CCM'}; rows=[]
 for p in ('plain','classical','dtls','pqc'):
  d=load(getattr(a,p)); rows.append({'Path':names[p],'Duration_h':fmt(d.get('Observed duration hours')),'Tx_OK':fmt(d.get('Sender successful messages'),0),'Tx_Fail':fmt(d.get('Sender failed messages'),0),'Success_percent':fmt(d.get('Sender success rate percent'),3),'Key_or_handshake_mean_ms':fmt(d.get('Key or handshake mean ms')),'RTT_mean_ms':fmt(d.get('Sender RTT mean ms')),'RTT_p95_ms':fmt(d.get('Sender RTT p95 ms')),'App_or_wire_B':fmt(d.get('Application payload bytes'),0)+'/'+fmt(d.get('Wire or protected bytes'),0)})
 out=Path(a.out_dir); out.mkdir(parents=True,exist_ok=True); fields=list(rows[0])
 with (out/'ten_hour_comparison.csv').open('w',newline='',encoding='utf-8') as f:w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(rows)
 md=['| Path | Hours | Tx OK | Tx fail | Success (%) | Key/HS mean (ms) | RTT mean (ms) | RTT p95 (ms) | App/wire (B) |','|---|---:|---:|---:|---:|---:|---:|---:|---:|']+[f"| {r['Path']} | {r['Duration_h']} | {r['Tx_OK']} | {r['Tx_Fail']} | {r['Success_percent']} | {r['Key_or_handshake_mean_ms']} | {r['RTT_mean_ms']} | {r['RTT_p95_ms']} | {r['App_or_wire_B']} |" for r in rows]
 (out/'ten_hour_comparison.md').write_text('\n'.join(md)+'\n',encoding='utf-8')
 tr='\n'.join(f"{esc(r['Path'])} & {r['Duration_h']} & {r['Tx_OK']} & {r['Success_percent']} & {r['Key_or_handshake_mean_ms']} & {r['RTT_mean_ms']} & {r['RTT_p95_ms']} & {r['App_or_wire_B']} \\\\" for r in rows)
 tex='\\begin{table*}[t]\n\\centering\n\\caption{Ten-hour same-board communication comparison.}\n\\label{tab:ten-hour-comparison}\n\\footnotesize\n\\begin{tabular}{lrrrrrrr}\n\\toprule\nPath & Hours & Tx OK & Success (\\%) & Key/HS mean & RTT mean & RTT p95 & App/wire (B) \\\\ \n\\midrule\n'+tr+'\n\\bottomrule\n\\end{tabular}\n\\vspace{1mm}\n\\parbox{0.98\\textwidth}{\\scriptsize Key/HS is not directly equivalent across paths: unavailable for plain CoAP, sender key establishment for the custom ECDH baseline, DTLS handshake for DTLS, and KEM plus HKDF for PQC. A dash means the firmware did not emit that metric.}\n\\end{table*}\n'
 (out/'ten_hour_comparison_table.tex').write_text(tex,encoding='utf-8'); print('[OK] comparison written to',out)
if __name__=='__main__':main()

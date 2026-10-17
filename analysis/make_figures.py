#!/usr/bin/env python3
"""Render publication figures from reproduce.py CSV outputs; requires matplotlib."""
import argparse
import csv
import json
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

ROOT=Path(__file__).resolve().parents[1]
COLORS={'PQC':'#007f80','DTLS':'#724cc5'}
plt.rcParams.update({'font.family':'DejaVu Sans','font.size':10,'axes.spines.top':False,
                     'axes.spines.right':False,'figure.facecolor':'white','savefig.facecolor':'white',
                     'axes.titleweight':'bold','svg.hashsalt':'pqc-iot-v1'})

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--results',type=Path,default=ROOT/'.reproduce/results')
    ap.add_argument('--out',type=Path,default=ROOT/'figures')
    args=ap.parse_args();args.out.mkdir(parents=True,exist_ok=True)
    summary=json.loads((args.results/'reproduced_summary.json').read_text())
    with (args.results/'rtt_samples.csv').open() as f:rows=list(csv.DictReader(f))
    fig,ax=plt.subplots(figsize=(8.8,4.8),layout='constrained')
    for profile in COLORS:
        values=sorted(float(r['rtt_ms']) for r in rows if r['profile']==profile)
        ax.step(values,[(i+1)/len(values) for i in range(len(values))],where='post',color=COLORS[profile],label=profile,lw=2)
    ax.set(xscale='log',xlabel='Successful protected-data RTT (ms, logarithmic scale)',ylabel='Cumulative fraction',ylim=(0,1.01),title='24-hour runs: successful-message latency')
    ax.grid(alpha=.15);ax.legend(loc='lower right')
    fig.text(.12,-.02,'Complete application profiles; different security work and timer boundaries.',fontsize=8,color='#526076')
    fig.savefig(args.out/'rtt_ecdf.png',dpi=180,bbox_inches='tight')
    fig.savefig(args.out/'rtt_ecdf.svg',bbox_inches='tight',metadata={'Date':None});plt.close(fig)
    with (args.results/'delivery_gaps.csv').open() as f:rows=list(csv.DictReader(f))
    fig,axes=plt.subplots(2,1,figsize=(8.8,5.3),sharex=True,layout='constrained')
    for ax,profile in zip(axes,COLORS):
        vals=[r for r in rows if r['profile']==profile]
        # Maximum gap in each one-minute bin retains recovery incidents while keeping SVG compact.
        bins={}
        for row in vals:
            key=int(float(row['hours_from_first_delivery'])*60)
            bins[key]=max(bins.get(key,0),float(row['gap_s']))
        ax.plot([k/60 for k in sorted(bins)],[bins[k] for k in sorted(bins)],color=COLORS[profile],lw=1.3)
        maximum=max(float(v['gap_s']) for v in vals)
        ax.set(ylabel='Gap (s)',title=f'{profile}: longest observed gap {maximum:.3f} s')
        ax.grid(alpha=.15)
    axes[-1].set(xlabel='Hours from first observed successful delivery',xlim=(0,24))
    fig.savefig(args.out/'delivery_continuity.png',dpi=180,bbox_inches='tight')
    fig.savefig(args.out/'delivery_continuity.svg',bbox_inches='tight',metadata={'Date':None});plt.close(fig)
    network=summary['network'];labels=['Baseline','+200 ms','10% loss','20% loss','50% loss'];x=list(range(5))
    fig,axes=plt.subplots(1,2,figsize=(10,4.6),layout='constrained')
    axes[0].bar([v-.17 for v in x],[n['structured_delivery_pct'] for n in network],width=.34,label='Structured terminal events',color='#9fd9cf')
    axes[0].bar([v+.17 for v in x],[n['completed_cycle_delivery_pct'] for n in network],width=.34,label='Completed cycles (raw audit)',color='#007f80')
    axes[0].set(ylim=(0,110),ylabel='Delivery success (%)',title='Denominator changes the result',xticks=x,xticklabels=labels)
    axes[0].tick_params(axis='x',rotation=25);axes[0].legend(loc='lower left',fontsize=8)
    bottoms=[0]*5
    for key,label,color in [('pk_fetch_failures','Public-key acquisition','#8199b5'),('metadata_failures_omitted_from_structured_totals','Metadata acquisition','#e6ac51'),('protected_data_retry_exhaustions','Protected-data retry exhaustion','#724cc5')]:
        values=[n[key] for n in network]
        axes[1].bar(x,values,bottom=bottoms,label=label,color=color)
        bottoms=[a+b for a,b in zip(bottoms,values)]
    axes[1].set(ylabel='Observed failed completed cycles',title='Where cycles fail',xticks=x,xticklabels=labels)
    axes[1].tick_params(axis='x',rotation=25);axes[1].legend(loc='upper left',fontsize=7.8)
    fig.savefig(args.out/'network_resilience.png',dpi=180,bbox_inches='tight')
    fig.savefig(args.out/'network_resilience.svg',bbox_inches='tight',metadata={'Date':None});plt.close(fig)
    print('Rendered six PNG/SVG figure files to',args.out)

if __name__=='__main__':main()

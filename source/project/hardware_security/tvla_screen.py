#!/usr/bin/env python3
"""First-order Welch screening of numeric trace matrices (rows=traces, columns=samples)."""
import argparse,json,sys
from pathlib import Path
import numpy as np
def screen(a,b,threshold=4.5):
    if a.ndim!=2 or b.ndim!=2 or len(a)<2 or len(b)<2 or a.shape[1]!=b.shape[1] or a.shape[1]==0:raise ValueError('need >=2 traces per class and equal, nonempty sample counts')
    if not np.isfinite(a).all() or not np.isfinite(b).all() or not np.isfinite(threshold) or threshold<=0:raise ValueError('trace values and positive threshold must be finite')
    delta=a.mean(0)-b.mean(0);variance=a.var(0,ddof=1)/len(a)+b.var(0,ddof=1)/len(b)
    # A constant sample has undefined Welch statistic, not a clean pass.
    if (variance<=0).any():raise ValueError('zero variance at one or more samples; check capture/export')
    t=delta/np.sqrt(variance)
    if not np.isfinite(t).all():raise ValueError('nonfinite t statistic')
    index=int(np.argmax(np.abs(t)));maximum=float(abs(t[index]))
    return {'fixed_traces':len(a),'random_traces':len(b),'samples':a.shape[1],'max_abs_t':maximum,'sample_index':index,'threshold':threshold,'screening_pass':maximum<threshold,'scope':'first-order screening only; a pass is not proof of leakage resistance'},t
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--fixed',required=True);ap.add_argument('--random',required=True);ap.add_argument('--threshold',type=float,default=4.5);ap.add_argument('--out',type=Path);ap.add_argument('--t-values',type=Path);a=ap.parse_args()
    try:
        result,t=screen(np.loadtxt(a.fixed,delimiter=',',ndmin=2),np.loadtxt(a.random,delimiter=',',ndmin=2),a.threshold)
        text=json.dumps(result,indent=2)+'\n'
        if a.out:a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(text)
        if a.t_values:a.t_values.parent.mkdir(parents=True,exist_ok=True);np.savetxt(a.t_values,t[None,:],delimiter=',')
        print(text,end='');return 0 if result['screening_pass'] else 1
    except (ValueError,OSError) as e:print(f'INVALID: {e}',file=sys.stderr);return 2
if __name__=='__main__':raise SystemExit(main())

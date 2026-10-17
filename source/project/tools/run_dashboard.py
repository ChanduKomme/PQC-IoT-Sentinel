#!/usr/bin/env python3
"""Start the bundled dashboard on the loopback interface."""
import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--port', type=int, default=8090)
    args = ap.parse_args()
    if not 1 <= args.port <= 65535:
        ap.error('port must be 1..65535')
    if not (ROOT/'dashboard/frontend/dist/index.html').is_file():
        ap.error('Frontend build missing. In dashboard/frontend, run npm ci then npm run build.')
    env = dict(os.environ, DASHBOARD_BIND='127.0.0.1', DASHBOARD_API_PORT=str(args.port))
    print(f'Dashboard: http://127.0.0.1:{args.port}', flush=True)
    return subprocess.call([sys.executable,'app.py'], cwd=ROOT/'dashboard/backend', env=env)

if __name__ == '__main__':
    raise SystemExit(main())

#!/usr/bin/env python3
"""Compatibility entry point for local defensive regression checks."""
import subprocess,sys
from pathlib import Path
raise SystemExit(subprocess.call([sys.executable,str(Path(__file__).resolve().parents[1]/'tools/run_host_checks.py')]))

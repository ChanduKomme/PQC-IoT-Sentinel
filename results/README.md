# Results

This directory contains machine-readable summaries of the quantitative results reported by the Version 1 conference manuscript.

## Files

- `primary_24h.csv` — primary PQC vs DTLS 24-hour application results.
- `network_resilience.csv` — secondary PQC delay/loss study, including both the original structured-terminal-event view and the corrected completed-cycle view.

## Denominator rule

The network-loss study intentionally keeps two views separate:

- **Structured delivery** comes from the archived selected terminal-event windows.
- **Completed-cycle delivery** comes from a versioned post-hoc reconstruction of preserved raw serial evidence and firmware semantics, including metadata-fetch failures that did not emit structured terminal failures.

The original sealed run directories were not modified by that reconstruction.

## Timing rule

Successful RTT statistics are conditioned on successful protected-data exchanges. They do not include all prerequisite setup/control work and should not be interpreted as full application deadlines.

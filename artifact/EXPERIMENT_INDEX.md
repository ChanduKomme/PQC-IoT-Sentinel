# Experiment index — Version 1

This file records the principal archived run identifiers used by the Version 1 study. The original sealed run directories are treated as immutable evidence.

## Official network-resilience runs

| Condition | Run ID | Original sealed manifest SHA-256 |
|---|---|---|
| Baseline | `baseline_official_20260926T164106Z` | `d943c810a3b298f86ca609270e80b3d5aa5a83d0642e2b02fffd734555b5b893` |
| +200 ms forward delay | `delay_200ms_official_20260926T220956Z` | `d914ded6afa0dacdfd2b426e02165d0cbeb6f89c41d53662226fa3453cf31ae7` |
| 10% random loss | `random_loss_10pct_official_20260927T095439Z` | `ed5de6ac0c4cc4d1326e8e5a17431e0738cbf6858e71ad158b648a3b7cba244a` |
| 20% targeted loss | `targeted_loss_20pct_official_20260927T113038Z` | `dbd72947899788b9f7531a30bfe003990adcb4ff84fc527f3a8d8564d64cd397` |
| 50% targeted loss | `targeted_loss_50pct_official_20260927T135247Z` | `692adc85e8384e4a844af805b67445f810e498faa923eb8e65b9d80c843736d1` |

## Invalid/diagnostic run exclusion

`random_loss_10pct_official_20260926T233003Z` is preserved only as a diagnostic/invalid attempt because the packet capture safety duration expired before the requested analysis sample was complete. It must not be used as the official 10% result.

A much earlier aborted baseline (`baseline_20260919T210153Z`) is also diagnostic only because the sender was not routed through the intended Raspberry Pi path.

## Structured-event vs completed-cycle analysis

The sealed official network summaries are the **structured-terminal-event view**.

A later post-hoc audit of preserved raw serial evidence and firmware source semantics found that metadata-fetch failure paths could complete without emitting a structured terminal `SEND_FAILED` event. The conference analysis therefore additionally reports a **completed-cycle view**.

Corrected completed-cycle delivery:

| Condition | Delivered | Completed cycles | Completed-cycle delivery |
|---|---:|---:|---:|
| Baseline | 1000 | 1000 | 100.00% |
| +200 ms | 1000 | 1000 | 100.00% |
| 10% loss | 1000 | 1000 | 100.00% |
| 20% loss | 991 | 1004 | 98.71% |
| 50% loss | 739 | 1126 | 65.63% |

At 20% loss the reconstructed failures comprise 3 public-key failures, 6 protected-data retry exhaustions, and 4 metadata failures.

At 50% loss they comprise 162 public-key failures, 99 protected-data retry exhaustions, and 126 metadata failures. Thus public-key + metadata acquisition account for 288 of 387 observed failed completed cycles.

## Retry-count semantics correction

`MSG_RETRY` is emitted after each timeout, including after the final exhausted timeout. Therefore `retry_events + 1` must not be interpreted as the number of transmissions for an exhausted cycle.

Corrected attempt outcome counts:

| Condition | Success on attempt 1 | Attempt 2 | Attempt 3 | Exhausted after attempt 3 | Extra transmissions |
|---|---:|---:|---:|---:|---:|
| Baseline | 1000 | 0 | 0 | 0 | 0 |
| +200 ms | 1000 | 0 | 0 | 0 | 0 |
| 10% loss | 913 | 81 | 6 | 0 | 93 |
| 20% loss | 798 | 160 | 33 | 6 | 238 |
| 50% loss | 413 | 210 | 116 | 99 | 640 |

## Evidence-preservation rule

The post-hoc completed-cycle correction is an additional derived-analysis layer. The sealed official run directories and their original manifest hashes are not modified.

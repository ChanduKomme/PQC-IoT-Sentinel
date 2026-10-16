# Measurement notes

## Primary unit of observation

The Version 1 paper separates several observation types rather than treating them as interchangeable:

- sender message outcomes;
- receiver acceptance/decryption evidence;
- session-establishment outcomes;
- successful-message RTT;
- inter-delivery gaps;
- packet-level forwarding observations;
- runtime resource samples.

## PQC timing boundary

The reported PQC protected-data RTT starts after public-key/metadata retrieval, KEM encapsulation, key derivation, and request construction. It includes protected-data transmission, receiver-side validation/decapsulation/decryption/persistence, ACK transmission, and sender ACK authentication.

Therefore, the reported successful RTT is **not** a full application-cycle latency.

## DTLS timing boundary

The reported DTLS application RTT begins around the protected write/read exchange after successful session establishment. Handshake establishment is measured separately.

The successful DTLS setup amortisation reported in the manuscript is based on observed successful handshake time divided by delivered messages under the actual reuse policy. It is not a per-request handshake latency.

## Successful-only distributions

Median, P95, P99, and maximum RTT distributions condition on successful deliveries. Failed and censored attempts belong in outcome/recovery reporting and must not be silently folded into successful RTT quantiles.

## Delivery continuity

Inter-delivery gap analysis uses host-observed timestamps of successive successful sender observations. These gaps include pacing, preparation, recovery, and collection delay; they are not direct measurements of radio outage duration.

## Network-resilience denominator correction

The original sealed network analyses selected structured terminal outcomes. Later source/raw-log auditing found that metadata-fetch failures could complete without a structured `SEND_FAILED` terminal event. The corrected completed-cycle denominator therefore differs at 20% and 50% loss.

Version 1 keeps both views visible:

- structured-terminal-event delivery;
- completed-cycle delivery.

## Packet loss

Packet-capture forward missing fractions describe routed receiver-bound UDP traffic, including control exchanges. They are not identical to application message-loss probability.

## Statistical scope

The primary campaigns are sequential long-running observations, not independent repeated deployments. Tens of thousands of message samples and hourly bins describe within-run behavior; they do not replace independent campaign-level replication.

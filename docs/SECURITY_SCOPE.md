# Security scope

## Evaluated PQC application properties

The Version 1 study describes an application-layer protected CoAP design with:

- receiver public-key fingerprint pinning;
- a Kyber-derived 512-parameter KEM flow;
- HKDF-SHA-256 key derivation;
- AES-256-CCM protected payloads;
- a separately provisioned device HMAC credential;
- sequence/freshness checks;
- persistent receiver acceptance state;
- request-bound authenticated positive acknowledgements;
- duplicate handling for the most recently committed request.

## Threat model boundary

The network adversary may observe, inject, modify, replay, delay, or discard traffic. Provisioning, endpoint code, and secret keys are assumed uncompromised for the intended message-security properties.

## Explicit limitations

Version 1 does not establish:

- FIPS 203 / ML-KEM conformance;
- formal protocol security;
- physical-board identity from a software-readable credential;
- forward secrecy after later compromise of the receiver's long-lived KEM secret;
- secure boot or trusted execution;
- hardware monotonic counters / anti-rollback;
- crash atomicity under arbitrary power loss;
- flash endurance;
- side-channel resistance;
- fault-injection resistance;
- target entropy quality;
- production credential-management security.

## DTLS comparison boundary

The DTLS 1.2 baseline uses ECDHE P-256, ECDSA P-256 server authentication, and AES-256-CCM, with channel reuse across requested 300-message sessions. It does not implement the same application-level sender credential and persistent commit-before-ACK rule.

For that reason, the two systems are not presented as security-equivalent. The paper compares observed complete-application behavior while explicitly retaining lifecycle and authentication differences.

## Development credentials

Development certificates/private keys and local secrets are not part of the public artifact. Any reproduction should generate new local credentials and must not treat development fixtures as production trust material.

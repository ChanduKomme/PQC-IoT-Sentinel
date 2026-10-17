# Wire v3 / security profile v4

This release is incompatible with wire-v2 applications. Rebuild and provision
both endpoints. `common/pqc_protocol.h` is the shared format definition.

## Protected data

CoAP POST `/pqkem-data`, confirmable, no token, UDP 5683. The integer fields below
are packed little-endian, as used by BL602. This project supports a restricted
CoAP subset with a maximum URI-path string length of 31 bytes. It rejects unknown
critical options. See [RFC 7252](https://www.rfc-editor.org/rfc/rfc7252) for the
underlying CoAP framing rules; the application format below is project-specific.

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 1 | type = 3 |
| 1 | 1 | wire version = 3 |
| 2 | 2 | KEM ciphertext length = 768 |
| 4 | 2 | plaintext/ciphertext length, 1..64 |
| 6 | 2 | reserved = 0 |
| 8 | 4 | receiver key ID |
| 12 | 4 | sender ID |
| 16 | 4 | positive sequence |
| 20 | 4 | credential generation |
| 24 | 12 | AES-CCM nonce |
| 36 | 768 | KEM ciphertext |
| 804 | N | AES-CCM ciphertext |
| 804+N | 16 | CCM tag |
| 820+N | 32 | device HMAC-SHA-256 tag |

HKDF input key material is the 32-byte KEM shared secret. Salt is empty; info is
the exact ASCII string `PQC-IOT-MLKEM512-AES256-CCM-v4`, without a terminating NUL.
The output is a 32-byte AES key. CCM uses the complete 36-byte header as AAD,
a 12-byte nonce and a 16-byte tag. HMAC uses the provisioned 32-byte device key
and covers header + KEM ciphertext + encrypted text + CCM tag.

Total protected payload is `852+N` bytes: **874** for the 22-byte demonstration.
The minimal CoAP wrapper adds 16 bytes: **890 bytes** of UDP application payload.
IPv4 and UDP headers add another 28 bytes without IP options. Wi-Fi/ethernet,
link encryption and retransmission costs require packet capture rather than
assuming this application size is full on-air overhead.

## Positive acknowledgement

The receiver returns CoAP ACK, code 2.04 Changed, matching message ID and
`pqkem-data` URI. Its payload is exactly 32 bytes:

`HMAC-SHA256(device_key, ASCII("PQC-ACK-v1") || request_device_hmac_tag)`

The domain prefix is exactly 10 bytes, without NUL. The request tag binds the
whole authenticated request, including its nonce, sequence and generation.
The sender verifies source address/port, CoAP response fields and this tag.
A plaintext `OK` is not accepted as delivery evidence. Negative responses remain
unauthenticated and cannot establish successful delivery.

The last accepted request's device tag is stored with its sender counter. A
valid identical request at that exact sequence can receive the same ACK again
without another decryption/acceptance. Earlier sequences and non-identical
same-sequence requests are rejected. The default nonce cache is additional RAM-only
screening; persistent sequence state is the primary reboot freshness mechanism.

## Persistent records and migration

Receiver store v9 uses EasyFlash key `pqc_gw_store_v9`. Its record includes the KEM
keypair, metadata, per-sender generation, counter, credential digest, last request
tag and CRC32. Compiled credentials reconcile at boot: same generation retains
freshness state; higher generation resets that sender; lower generation is refused.

Sender store v4 uses `pqc_s_<sender-id-hex>_<generation-hex>`. The on-flash
`next_counter` is an exclusive reserved boundary, not the next RAM value to send.
Before using a range, a sender saves/verifies its new boundary. A reboot starts
at the boundary and reserves another range of 256. Writes must succeed before
using the range. No hardcoded absolute raw flash sector is used by this sender.

The v9 receiver record is intentionally separate from the old uploaded v8 record.
On the first upgrade it generates a new receiver key if the new namespace is absent.
Capture and pin the new fingerprint through the trusted setup procedure. Flashing
must preserve the SDK's own reserved storage and compatible partition layout.
A CRC/readback check is not a hardware anti-rollback mechanism.

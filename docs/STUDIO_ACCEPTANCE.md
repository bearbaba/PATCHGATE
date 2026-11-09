# PATCHGATE — GenLayer Studio acceptance

## Setup

1. Open https://studio.genlayer.com/ on Studionet (chain ID 61999; not 61997).
2. Deploy contracts/patchgate.py as PatchGate; record the actual contract address and deployment TX hash.
3. Use signer A to create releases. All calls are signed.
4. After each write, require FINALIZED / GenVM SUCCESS, not FINALIZED alone. Read get_release(id) at LATEST_FINAL, recording the actual TX hash, release ID, stage, decision, evidence digest and consensus result.

## Case A — affected release (BLOCK)

Signer A calls:
- open_release("npm", "lodash", "4.17.11", "[\"GHSA-jf85-cpcp-j695\"]")
- Note returned release ID (do not assume it is 1).
- evaluate_release(id)

Expected if current official advisory data is accessible: decision BLOCK; stage EVALUATED; authorized false; nonempty SHA-256 evidence. Calling authorize_release(id) must be rejected and state must remain unchanged.

## Case B — advisory-scoped clearance (ALLOW)

Signer A calls:
- open_release("npm", "lodash", "4.17.12", "[\"GHSA-jf85-cpcp-j695\"]")
- evaluate_release(new_id): expected ALLOW for this selected advisory only.
- authorize_release(new_id): expect AUTHORIZED / true after successful finalization.
- Duplicate authorize_release(new_id) must fail.
- revoke_release(new_id): expect REVOKED / false.
- Duplicate revoke_release(new_id) must fail.

Do not describe lodash 4.17.12 as generally safe: other advisories exist.

## Case C — unavailable source (REVIEW_REQUIRED)

Signer A calls:
- open_release("npm", "lodash", "4.17.11", "[\"OSV-2099-NOT-FOUND\"]")
- evaluate_release(new_id): expected REVIEW_REQUIRED or nonfinalizing source/consensus failure, never ALLOW.
- Attempt authorization must fail.

## Case D — roles and replay

Switch to signer B and try authorize_release or revoke_release on A's release: owner-only rejection. Try evaluate_release on an already EVALUATED release: rejection.

## Evidence template — replace blanks with actual on-chain facts

| Case | Release ID | TX hash | GenVM result | Consensus | Readback |
| --- | --- | --- | --- | --- | --- |
| BLOCK evaluation | | | | | |
| BLOCK authorization refusal | | | | | |
| ALLOW evaluation | | | | | |
| ALLOW authorization | | | | | |
| Revocation | | | | | |
| REVIEW source failure | | | | | |
| Wrong signer and replay | | | | | |

Never invent hashes, IDs, source values, or consensus results. The OSV API can change between validators; strict evidence equality is intentionally fail-closed. Authorization is limited to a caller-chosen advisory list.

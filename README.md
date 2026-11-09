# PATCHGATE

**Advisory-scoped, validator-verified software release authorization for GenLayer.**

PATCHGATE is a standalone Python Intelligent Contract for release decisions tied to an **exact ecosystem, package, version and explicit set of OSV advisories**. GenLayer validators independently fetch official OSV data and compare material decision fields and evidence digests. A state machine then gates a one-time, owner-only release authorization.

## Core workflow

1. **Register:** owner freezes ecosystem, package, version and 1–3 advisory IDs via open_release.
2. **Evaluate:** evaluate_release asks independent GenLayer validators to fetch https://api.osv.dev/v1/vulns/{id}, match the package and determine the version's advisory-specific status. Explicit affected versions are handled mechanically; range semantics use independently validated AI judgment.
3. **Record:** each advisory's status and normalized OSV evidence SHA-256 is stored with the decision.
4. **Authorize:** owner may call authorize_release only for ALLOW.
5. **Revoke:** owner may revoke_release once. Later reevaluation requires a new release request.

## Decisions and boundaries

| Decision | Meaning | Authorizable? |
| --- | --- | --- |
| BLOCK | A selected advisory affects this exact version. | No |
| REVIEW_REQUIRED | Selected advisory evidence is unavailable, malformed, inconsistent or ambiguous. | No |
| ALLOW | No *selected* advisory is known to affect this exact version. | Yes; owner only |

**ALLOW is NOT a general security certification** or a dependency-wide vulnerability scan. It applies solely to caller-selected advisories and the observed source snapshot. PATCHGATE does not attest deployed artifacts, runtime exploitability, undocumented advisories or future OSV updates. Reassessment after new advisories requires a new release record.

## Contract / verification

- [Standalone Intelligent Contract](contracts/patchgate.py)
- [Mocked GenLayer VM unit tests](tests/test_patchgate.py) — 11 cases: role enforcement, missing source, duplicated advisories, adversarial validator mismatch, blocking, replay and revocation.
- [GitHub Actions checks](https://github.com/bearbaba/PATCHGATE/actions/workflows/tests.yml)
- [Studio deployment and signed acceptance instructions](docs/STUDIO_ACCEPTANCE.md)
- [Ready-to-enter example call arguments](examples/cases.json)

Local tests: python -m unittest discover -s tests -v

GenVM static and ABI checks: pip install genvm-linter ; genvm-lint check contracts/patchgate.py

## Concrete OSV fixture

Under [GHSA-jf85-cpcp-j695](https://osv.dev/vulnerability/GHSA-jf85-cpcp-j695), lodash before 4.17.12 is affected. Target examples for GenLayer Studio: npm / lodash / 4.17.11 => BLOCK; npm / lodash / 4.17.12 => ALLOW for **that advisory only**. These are acceptance expectations, not claims of on-chain execution.

## Status

Source and offline test suite are committed. **No GenLayer Studio deployment, finalized transaction or steward acceptance is claimed yet.** Python mock tests alone are insufficient for a GenLayer submission.

Sources: [GenLayer Equivalence Principle](https://docs.genlayer.com/developers/intelligent-contracts/equivalence-principle) · [OSV API](https://google.github.io/osv.dev/api/).

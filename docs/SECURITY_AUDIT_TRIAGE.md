# Security audit of v1.23.7 — triage and status

The audit (15 findings plus 3 non-security notes) was run against commit
`f5ea44e`. Each finding was checked against the code rather than taken on
trust; "verified" below means read in the code and, where stated, reproduced
or covered by a failing-then-passing test. Reachability matters as much as
the flaw, so it is recorded separately.

## Findings

| # | Audit severity | What I verified | Reachable today? | Status |
|---|----------------|-----------------|------------------|--------|
| 1 | Critical | Confirmed. `original_filename` was stored unchecked and joined onto the temp directory by Open; reproduced on Linux with `../../x` (the returned path left the temp dir). | **Latent.** `FileTransferManager`, the only producer of vault entries from a peer's `file_offer`, is never instantiated in `core/` or `app/`. Vault entries today come from `/secure move` on the user's own files (already `os.path.basename`'d). Exploitable once that path is wired in, or if the on-disk metadata is tampered with. | **Fixed 1.23.11** (stored name, Open) |
| 2 | Critical | Traversal on Export: confirmed. The claim that Export **executes** the file is **not accurate**: `os.startfile`/`xdg-open` exist only on the Open path, which screens a dangerous-extension list and magic bytes; Export only writes to the downloads directory. | Latent (same reason as #1) | **Fixed 1.23.11** (Export path) |
| 3 | High | Confirmed by reading. `_on_group_join_response` never checks that the user sent a join request for that group (the only `make_group_join_request` records nothing), and for an unknown `group_id` it creates the `Group` with the admin key taken from the discovery registry, which any LAN UDP/mDNS announce can populate; the response is then verified against that same key. | Yes, for an attacker who can open an authenticated connection to the victim | **Open — needs a design decision** |
| 4 | High | Confirmed and reproduced. Both handshake flows wrote a first-seen row (or bumped `last_seen`) before verifying the signature; a deliberately wrong signature still left a `PENDING` row with an attacker-chosen name. | Yes | **Fixed 1.23.9** |
| 5 | High | Confirmed by reading `authorize_relay_request`: relay mode, the requester's membership and target connectivity are checked, the target's membership is not. | Yes, for a group member | **Open — policy decision** |
| 6 | High | **Not yet verified.** | — | Open |
| 7 | Medium | Confirmed by reading: `set_policy` skips authorization when `admin_device_id` is unset, and the policy signature is stored but never verified. Reachability (does a peer ever push a policy?) not checked. | Unknown | Open |
| 8 | Medium | Confirmed by reading: `check_external_trust` returns silently when `list_groups()` raises, so it fails open although its docstring claims fail-closed. | Yes, when the store errors | **Open — decision** (fail closed vs. availability) |
| 9 | Medium | Plausible; not reproduced. Needs a symlink planted in the downloads directory, i.e. local write access. | Local only | Open, low priority |
| 10 | Medium | Confirmed. Device names, NTFS streams, trailing dots and over-long names were accepted by `resolve_safe_dest_path`. | **Yes**, through the normal accept flow, on Windows | **Fixed 1.23.11** |
| 11 | Medium | Plausible; not reproduced. A local race between validation and creation. | Local only | Open, low priority |
| 12 | Medium | **Not yet verified.** | — | Open |
| 13 | Low | Confirmed. The keyfile and its directory were created with default modes, and the fixed temp name followed a planted symlink (shown by a test against the old code). | Local only | **Fixed 1.23.10** (POSIX modes; on Windows the ACL is inherited) |
| 14 | Low | **Partly mitigated.** Chat and transfer events carry the self-reported `sender_id` but also the handshake-derived `peer_device_id`. Whether the UI uses the former for any decision was not checked. | Unknown | Open |
| 15 | Low | **Not yet verified.** | — | Open |

## Non-security notes in the audit

- `tests/test_e2e_resume.py` could never run (it used a `ConnectionManager` API that does not exist). Rewritten and stabilised in 1.23.8 and 1.23.9.
- `core/benchmarking.py` imported the POSIX-only `resource` module at module level, so on Windows the suite died during collection. Fixed in 1.23.12: without `resource`, `peak_rss_mb()` returns `0.0` ("not measured"); no Windows-specific measurement was added because it cannot be tested here.
- The three `test_reliability_cases.py` failures read the real `~/.peerc/identity.json`. Not changed; they pass on CI and on a clean HOME.

## Clean areas the audit confirmed

Nonce derivation, HKDF domain separation, scrypt parameters, frame-length
parsing, identity-before-trust ordering, group admin enforcement on
join/leave/revocation, relay/rendezvous authorization from the handshake
identity, markup escaping of peer chat text, no `shell=True`, and atomic
writes.

## Decisions needed before the open High items can be fixed

- **#3**: record the join requests a user sends and accept a response only for one of them, from the connection whose authenticated device id is that group's admin, taking the admin key from the handshake rather than the discovery registry.
- **#5**: require the relay target to be an active member of the group (the conservative default), or document the intended exception.
- **#8**: fail closed (deny external trust when the group store cannot be read), at the cost of refusing trust decisions while the store is broken.
- **#6, #12, #15**: choose limits (pending handshakes, frame size before authentication, pending join requests, locator entries per member).

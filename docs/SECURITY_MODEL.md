# Security Model, Key Lifecycle & Revocation

Status: **adopted as the authoritative security/threat-model document for
peerc**, per explicit decision to adopt this specification wholesale. This
supersedes the informal, scattered threat-model notes in `BUG_REPORT.md`
for anything covered here — `BUG_REPORT.md` remains the record of
specific bugs found/fixed, this document is the standing security model
the project holds itself to going forward.

Cross-references to what's already implemented are added inline
(`[Phase N]`) so this reads as the model *for this specific codebase*,
not a generic spec. Two integration points needed explicit resolution
before adoption — both resolved, and called out at the relevant section
(§15, key rotation; the Group Authority interaction is in
`GROUP_AUTHORITY_DESIGN.md` since it depends on that system too).

---

## 1. Security Goals

peerc bertujuan menyediakan:

1. Authenticated peer identity
   - Peer dapat membuktikan kepemilikan identity cryptographic. **[Phase 3 — Ed25519, implemented]**
2. End-to-end confidentiality
   - Chat dan file tidak dapat dibaca oleh relay, rendezvous, atau network observer. **[Phase 6-9 — handshake + AEAD, implemented]**
3. Integrity
   - Pesan, file, policy, dan authorization tidak dapat dimodifikasi tanpa terdeteksi.
4. Forward secrecy
   - Kompromi long-term identity key tidak otomatis membuka session lama. **[Phase 7 — ephemeral X25519, implemented]**
5. Managed authorization
   - Administrator dapat mengontrol membership dan policy group. **[Phase 42 — Group Authority, planned]**
6. Device revocation
   - Device yang hilang, dicuri, atau tidak lagi diizinkan dapat dicabut aksesnya. **[Phase 4 — local revocation, implemented; propagation is Phase 42]**
7. Auditable administration
   - Tindakan administrator penting dapat dicatat dan diverifikasi. **[Phase 41 — Security Event Logging, planned]**

---

## 2. Security Boundaries

peerc membedakan beberapa jenis authority.

```
                    peerc Security
                         │
        ┌────────────────┼────────────────┐
        │                │                │
     Identity        Transport        Authority
        │                │                │
     Ed25519       X25519 + AEAD      Group Admin
        │                │                │
        ▼                ▼                ▼
      WHO?           PRIVATE DATA?    ALLOWED?
```

Identity — «"Siapa perangkat ini?"» — long-term Ed25519 key **[Phase 3]**.

Transport — «"Bagaimana dua peer membuat encrypted session?"» — ephemeral
X25519 dan AEAD **[Phase 6-9]**.

Authority — «"Apa yang boleh dilakukan perangkat ini?"» — membership,
policy, permissions, dan administrator signatures **[Phase 42]**.

Ketiga fungsi tersebut tidak boleh digabung menjadi satu key.

---

## 3. Threat Model

peerc harus menganggap network sebagai untrusted environment.

Attacker dapat:

- melihat traffic jaringan
- merekam packet
- memodifikasi packet
- menghapus packet
- melakukan replay
- mengirim packet palsu
- mengetahui IP/port peer
- mencoba impersonasi device
- membuat device identity palsu
- mencoba discovery spoofing
- mencoba memanipulasi endpoint
- mencoba mengirim file dengan metadata berbahaya
- mencoba melakukan resource exhaustion
- mendapatkan akses ke sebagian filesystem
- mendapatkan akses ke database jika storage protection gagal

peerc harus mengasumsikan bahwa:

```
Internet   → UNTRUSTED
LAN        → UNTRUSTED
Wi-Fi      → UNTRUSTED
Discovery  → UNTRUSTED
IP address → UNTRUSTED
```

---

## 4. Network Attacker

Attacker dapat berada di jaringan yang sama.

```
Attacker
    │
    ├── sniff
    ├── spoof
    ├── replay
    └── modify
         │
         ▼
       peerc
```

Security requirement:

- plaintext tidak boleh dikirim melalui network setelah encrypted transport aktif **[Phase 9]**
- packet modification harus terdeteksi **[Phase 8 — AEAD tag]**
- replay harus ditolak **[Phase 8 — sequence enforcement, implemented]**
- identity harus diverifikasi cryptographically **[Phase 6]**
- discovery announcement tidak boleh otomatis dipercaya **[Phase 4 — TOFU]**

Network attacker tidak boleh dapat membaca isi chat/file hanya karena
berada di LAN yang sama.

---

## 5. Identity Impersonation

IP address tidak dianggap sebagai identity.

Tidak aman: `45.10.20.30 → "Ini pasti Device A"`

Yang benar:

```
IP → candidate locator → handshake → Ed25519 signature → known public key? → Device A
```

Attacker yang mengetahui IP Device A tetap tidak dapat mengklaim identity
A tanpa private key A. **[Phase 6, implemented]**

---

## 6. Endpoint Spoofing

Endpoint update harus ditandatangani oleh identity device — lihat
`INTERNET_CONNECTIVITY_DESIGN.md` §Endpoint Update untuk mekanisme
lengkap (Phase 44).

```
Device A → Endpoint Update → Ed25519 Signature
```

Peer menerima: verify signature, device identity, timestamp, nonce. Jika
signature tidak valid: **REJECT**.

---

## 7. Replay Protection

Handshake dan security-sensitive messages harus memiliki mekanisme
anti-replay — minimal cryptographic nonce, timestamp, session identifier,
monotonically tracked state jika diperlukan. **[Phase 6 — NonceCache;
Phase 8 — sequence counter; both implemented]**

Request yang sudah digunakan tidak boleh diterima kembali.

---

## 8. Forward Secrecy

Long-term identity key tidak boleh langsung menjadi session encryption key.

```
Ed25519 → authenticate

X25519 ephemeral → session key material → HKDF → Session Keys
```

**[Phase 6/7, implemented]**. Long-term key compromised → future
authentication at risk → old recorded sessions NOT automatically
decryptable (selama ephemeral session keys tidak ikut dikompromikan).

---

## 9. Administrator Threat Model

Administrator adalah trusted authority, tetapi tidak boleh dianggap
omnipotent. **[Phase 42]**

Admin memiliki authority untuk: approve/reject membership, revoke
devices, modify group policy, approve protected operations, authorize
export, control communication permissions.

Admin **tidak otomatis** memiliki: private key member, session
encryption keys, plaintext chat, plaintext files, kemampuan membaca E2E
traffic.

```
Admin Authority
      ├── Membership ✓
      ├── Policy ✓
      ├── Revocation ✓
      ├── Export approval ✓
      │
      └── Decrypt member chat ✗
```

---

## 10. Administrator Compromise

Kompromi administrator adalah high-impact security event.

```
Attacker → Admin Private Key → fake membership / fake policy /
           revoke devices / approve operations / impersonate authority
```

peerc tidak dapat menganggap signature admin yang valid sebagai "pasti
dibuat oleh manusia yang sah". Cryptography hanya membuktikan: «Signature
dibuat oleh pihak yang memiliki private key tersebut.» Jika private key
admin dicuri, attacker dapat menggunakan authority tersebut.

---

## 11. What Admin Compromise Does NOT Automatically Give

```
Admin key stolen
       ├── forge future policy       ✓
       ├── revoke membership        ✓
       ├── approve future export    ✓
       └── decrypt old P2P sessions ✗
```

Dengan catatan session encryption dan key lifecycle diterapkan dengan
benar (§8). Attacker yang menguasai admin tetap dapat menyebabkan
kerusakan ke depan (authorization palsu, mengubah membership).

---

## 12. Admin Key Protection

Admin private key harus memiliki protection lebih tinggi dibanding
ordinary device key.

```
Group Root Authority → Admin Identity Key → OS Secure Storage / Hardware-backed Storage
```

Jika tersedia: TPM, Secure Enclave, Android Keystore, platform
credential/key storage. Private key tidak boleh disimpan plaintext
(`admin.key`, atau `{"private_key": "..."}` di config.json) — matches
the existing `KeyStore` rule from Phase 3 exactly, applied to admin keys
specifically.

---

## 13. Ordinary Device Key Lifecycle

```
GENERATE → STORE → ACTIVE ──┬── ROTATE → NEW KEY → ACTIVE
                             └── REVOKE → INVALID
```

**[Phase 3/4 implement GENERATE/STORE/ACTIVE/REVOKE already. ROTATE is
new — Phase 40.]**

---

## 14. Key Generation

```
Generate Ed25519 keypair
        ├── Private Key → secure storage
        └── Public Key → Device ID = SHA-256(Ed25519 Public Key)
```

**[Phase 3, implemented exactly this way.]** Private key tidak pernah
diperlukan oleh peer lain.

---

## 15. Device Key Rotation

Key rotation diperlukan ketika: policy perusahaan mewajibkannya, key
sudah terlalu lama, terdapat suspected compromise, device melakukan
security migration, algoritma/key format berubah.

**Integration note (resolved):** `device_id = SHA256(public_key)`
[Phase 3] means rotating the key necessarily changes the `device_id` —
unlike an IP/locator change, which never touches identity at all. This
is a real structural difference from `INTERNET_CONNECTIVITY_DESIGN.md`'s
Endpoint Update, not just a cosmetic one. Resolved as: **Phase 40
introduces a `TrustStore`-tracked identity chain** — a device's trust
record keeps a history of every `device_id` it has ever rotated through,
each transition proven by a **Transition Certificate** (old key signs
new key). A peer that already trusts the old `device_id` verifies the
transition certificate and carries `TRUSTED` status forward to the new
`device_id` automatically — no fresh TOFU approval needed, same
continuity goal as Endpoint Update serves for locators, achieved the
same way (a signature chain a peer can verify, not a claim it has to
just believe).

```
Old Identity Key
       │ signs
       ▼
New Identity Key
```

Peer dapat memverifikasi bahwa: `Old Key → authorized New Key`. Jika
rotation tidak dapat dibuktikan:

```
Old Device → NEW KEY → UNKNOWN IDENTITY
```

harus diperlakukan sebagai security event (§29, WARNING severity at
minimum).

---

## 16. Key Compromise

```
COMPROMISED → REVOKE OLD KEY → GENERATE NEW KEY → ADMIN APPROVAL (if in a group) → NEW MEMBERSHIP
```

Device ID berdasarkan old public key tidak boleh terus dianggap valid —
unlike planned rotation (§15), a compromise-triggered rotation carries
**no** transition certificate from the compromised key (it can't be
trusted to sign its own successor), so peers must treat the new identity
as genuinely new and re-establish trust via TOFU again, deliberately not
auto-carried-over.

---

## 17. Revocation

```
PENDING → TRUSTED → REVOKED
```

**[Phase 4, implemented — `TrustStatus` enum matches exactly.]**
"REVOKED" harus menjadi state terminal untuk identity/key tersebut.

---

## 18. Revocation Record

Administrator dapat membuat signed revocation record — full schema and
propagation mechanics in `GROUP_AUTHORITY_DESIGN.md` (Phase 42). Peer
memverifikasi signature authority sebelum menerima revocation.

---

## 19. Revocation Propagation

Karena peerc adalah P2P, revocation tidak selalu dapat diketahui seluruh
device secara instan.

```
Admin → Revokes Device A
          ├── B receives revocation ✓
          ├── C receives revocation ✓
          └── D offline → doesn't know yet
```

Saat D kembali online, D harus melakukan synchronization terhadap group
authority atau peer yang memiliki authoritative state.

---

## 20. Fail-Closed Policy

Untuk security-sensitive operations, status yang tidak diketahui
sebaiknya tidak dianggap valid.

```
Membership status unknown → Sensitive operation → DENY
```

Terutama untuk: export, trust external device, membership changes,
protected group communication, key replacement. Matches the fail-closed
default already decided for executable detection in
`SECURE_STORAGE_DESIGN.md` §6/§11.6 — same principle, applied here to
authorization instead of file-type detection.

Namun policy dapat menyediakan offline grace period untuk operasi biasa
agar group tidak sepenuhnya unusable ketika admin sementara offline.

---

## 21. Admin Key Rotation

```
Admin Key A → signed transition → Admin Key B → ACTIVE
```

Jika Admin A compromised: `Admin A → REVOKED`, `Admin B → ACTIVE`. Group
harus memiliki cara untuk menentukan root authority terbaru.

---

## 22. Multi-Admin Security

```
3 Admins: A, B, C — Policy: 2 of 3 required

Critical Export → Requires 2 Admin signatures
    ├── Admin A ✓
    ├── Admin B ✓
    └── Admin C -
    → APPROVED
```

Dapat diimplementasikan menggunakan cryptographic signatures tanpa
blockchain. Full design in `GROUP_AUTHORITY_DESIGN.md` §Multiple
Administrators.

---

## 23. Key Hierarchy

```
                    Group Authority
                          │
                    Admin Identity
                          │
                 signs group policies
                          │
              ┌───────────┴───────────┐
              │                       │
       Membership Cert          Policy/Capability
              │                       │
              ▼                       ▼
         Device Identity          Permission
          Ed25519 Key
              │
              ▼
       Ephemeral X25519
              │
              ▼
         Session Keys
              │
              ▼
        AEAD Encryption
```

Setiap level memiliki tujuan berbeda.

---

## 24. Secure Storage Key Lifecycle

```
OS Secure Storage → Master Key → Database encryption / Secure file encryption / Sensitive metadata
```

**[Phase 39 — implemented as design, no code yet. This document's "Master
Key" is `SECURE_STORAGE_DESIGN.md`'s DEK/KEK envelope, same concept,
already resolved to Scrypt + whole-file-via-in-memory-SQLite there —
this section doesn't re-decide that, just confirms consistency.]**

Master key tidak disimpan plaintext bersama database. Recovery mechanism:

```
Recovery Code → KDF → Key Encryption Key → unwrap Master Key
```

**[Matches `SECURE_STORAGE_DESIGN.md` §2-3 exactly.]**

---

## 25. Compromise of Local Device

```
OS compromised
     ├── private key potentially accessible
     ├── plaintext while application is running
     ├── decrypted files potentially accessible
     └── session data potentially accessible
```

peerc tidak dapat menjamin confidentiality terhadap attacker yang telah
mendapatkan full control atas endpoint saat data sedang digunakan.
Encryption protects primarily network traffic, stored data at rest, and
unauthorized remote access — bukan endpoint yang sudah sepenuhnya
compromised. **Matches the "malware while unlocked" limitation already
stated explicitly in `SECURE_STORAGE_DESIGN.md` §1 — same honesty,
consistent across both documents.**

---

## 26. Malicious Member

Member yang valid dapat menjadi malicious (unauthorized export attempts,
external trust attempts, malicious files, policy bypass attempts). peerc
harus mengandalkan authorization pada core:

```
Request → Identity → Membership → Policy → Permission → Action
```

Valid membership tidak berarti semua action diperbolehkan. Matches the
existing project principle "Policy Must Be Enforced by Core" (§33 in
`GROUP_AUTHORITY_DESIGN.md`) and the established pattern of validating
in `core/`, not trusting the UI layer, already used throughout
(`validate_message()` in `core/protocol/messages.py`, `KeyStore`'s
refusal to silently downgrade, etc).

---

## 27. Data Exfiltration Limitation

peerc dapat mengontrol export, file transfer, external trust, dan group
communication — tetapi tidak dapat menjamin user tidak akan memotret
layar, mengetik ulang informasi, menggunakan kamera eksternal, dsb.

«peerc adalah authorization and secure communication system, bukan DRM
absolut.»

---

## 28. Administrator Compromise Recovery

```
Detect compromise → Freeze sensitive operations → Revoke old Admin Key →
Generate new Admin Key → Establish new authority → Revalidate group
policy → Audit affected operations
```

Jika multi-admin tersedia, recovery dapat dilakukan menggunakan remaining
trusted administrators.

---

## 29. Security Event Severity

**[Phase 41 — Security Event Logging, planned; extends the existing
Phase 28 "Logging" plan with this classification scheme specifically.]**

```
INFO      — endpoint changed, normal key rotation
WARNING   — unknown device, identity changed, failed authentication
HIGH      — revoked device attempted connection, repeated auth failures, suspicious authorization
CRITICAL  — admin key compromise, identity private key compromise, invalid authority chain
```

---

## 30. Security Assumptions

- **A. Cryptographic Libraries** — peerc menggunakan cryptographic
  library yang matang dan tidak mengimplementasikan algoritma
  cryptography sendiri. **[Already the project's stated policy — see
  IMPLEMENTATION_PLAN.md Phase 3's explicit instruction and every crypto
  module built so far using only `cryptography`.]**
- **B. Operating System** — OS device dianggap memiliki security
  boundary yang wajar. Jika OS sepenuhnya compromised, confidentiality
  endpoint tidak dapat dijamin.
- **C. Private Key Protection** — Private key diasumsikan terlindungi
  oleh secure storage dan access controls platform.
- **D. Correct Randomness** — Cryptographic randomness dari operating
  system dianggap aman.
- **E. Administrator** — Administrator dianggap trusted authority untuk
  policy group. Namun administrator tetap dapat dikompromikan.
- **F. User Verification** — Pada first trust atau key change,
  user/admin harus dapat memverifikasi identity/fingerprint melalui
  mekanisme yang sesuai. **[Phase 4's TOFU fingerprint display, and
  `SECURE_STORAGE_DESIGN.md`'s fingerprint formatting, already implement
  the mechanism this assumption depends on.]**

---

## 31. Security Guarantees

```
Network Observer   → Cannot read E2E traffic
Network Attacker   → Cannot impersonate known device without its private key
Modified Packet    → Detected
Replay             → Rejected
Changed IP         → Identity remains unchanged
Revoked Device     → Rejected after revocation state is known
```

---

## 32. Security Non-Guarantees

```
❌ Device cannot be physically stolen
❌ Compromised OS cannot access plaintext in memory
❌ User cannot photograph screen
❌ Admin cannot abuse valid authority
❌ Revocation propagates instantly while peers are offline
❌ Pure P2P can always rediscover two peers that both
   changed locator while simultaneously offline
❌ Encryption can recover lost keys
```

Stated this plainly rather than implied — matches the project's existing
style of honest limitation-disclosure (`SECURE_STORAGE_DESIGN.md` §1's
threat #3, the viewer-cache "best-effort, not a guarantee" language in
§10 there).

---

## 33. Core Security Principle

```
             IDENTITY
                 │
              "WHO?"
                 │
              Ed25519
                 │
                 ▼
             AUTHENTIC
                 │
                 ▼
             MEMBERSHIP
                 │
              "ALLOWED?"
                 │
              Policy
                 │
                 ▼
            AUTHORIZATION
                 │
                 ▼
             X25519
                 │
              "PRIVATE?"
                 │
                 ▼
          ENCRYPTED SESSION
```

Tidak ada satu key yang memiliki seluruh fungsi.

---

## 34. Final Key Lifecycle

```
                    Generate
                       │
                       ▼
                    Active
                       │
            ┌──────────┼──────────┐
            │          │          │
         Rotate     Suspected   Compromised
            │       compromise      │
            │          │             │
            ▼          ▼             ▼
       New Identity   Investigate   Revoke
            │                        │
            ▼                        ▼
      Transition Cert           New Keypair
            │                        │
            └──────────┬─────────────┘
                       ▼
                 Re-enrollment
                       │
                       ▼
                     Active
```

---

## 35. Final Revocation Model

Revocation harus bersifat cryptographically authoritative, bukan hanya
menghapus entry dari database lokal.

```
Admin Authority → Signed Revocation → Peer receives → Verify authority →
Mark identity REVOKED
    ├── reject new connections
    ├── reject authorization
    ├── reject membership actions
    └── terminate active sessions where policy requires
```

Active session yang berasal dari device yang baru saja dicabut harus
dapat dihentikan berdasarkan revocation policy.

---

## 36. Security Design Summary

```
IDENTITY        Ed25519          → stable device identity
LOCATION        IP/IPv6/Port     → temporary locator
AUTHENTICATION  Ed25519 sigs     → prove identity
KEY EXCHANGE    Ephemeral X25519 → forward-secret session
ENCRYPTION      AEAD             → confidentiality + integrity
AUTHORITY       Admin signatures → membership + policy
REVOCATION      Signed revocation → remove authority
AUDIT           Signed security events → accountability
```

**Fundamental Security Principle**

«peerc does not trust the network. It trusts cryptographic identity and
explicitly authorized policy.»

«Administrator authority controls what a device may do, but does not
inherently grant access to E2E encrypted content.»

«A key compromise is treated as a security event requiring revocation
and re-enrollment, not as something cryptography can magically recover
from.»

---

## 37. Self-Reported Display Metadata (Name, Device Model)

`name` (display name, Phase 3.3) and `model` (device/platform string,
Phase 3.4, `core/device_info.py`) are shown next to a peer's identity
in the UI — but neither is ever an input to a trust or security
decision. The only thing that identifies a device is its Ed25519
`device_id` (§5). A device is free to announce any `name`/`model` it
wants; peerc never treats agreement or disagreement between them and
anything else as evidence of anything.

Their purpose is narrower and purely human: helping a person doing
*manual* verification (deciding whether to trust a newly-seen device,
§7 New Device UX in `DESIGN.md`) cross-check "is this really my
friend's phone" against what they already know, alongside the
cryptographic fingerprint — never a replacement for it.

`model` is deliberately **not persisted** anywhere (not in
`identity.json`, not in the vault). It's recomputed fresh from
`platform`/environment detection every time the app starts. Persisting
it once at identity creation would mean restoring or importing that
identity onto different physical hardware keeps showing the *original*
device's model forever — actively misleading for exactly the manual
cross-check this field exists for. `name`, by contrast, is intentionally
persisted (`identity.json`) and user-settable (`/name`, or the
first-run `NameSetupModal`) — it's a chosen label, not a hardware fact.

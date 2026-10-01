# Group Authority System

Status: **design, no code yet** — reference for Phase 42/43
(`IMPLEMENTATION_PLAN.md`). Adapted from the provided specification;
project name aligned to `peerc`, and the Export Authorization / personal
Secure Storage integration question is resolved explicitly (§Export
Authorization) per an explicit decision: **the two work together, not as
alternatives.**

---

## 1. Overview

peerc menggunakan arsitektur P2P data plane dengan centralized authority
pada control plane.

Dua sistem utama:

1. **Group Authority System** — administrator mengatur membership,
   trust, permissions, dan policy tanpa menjadi server komunikasi.
2. **Internet P2P Connectivity System** — lihat
   `INTERNET_CONNECTIVITY_DESIGN.md` (Phase 44-46).

```
Data Plane
Peer A <══════════════> Peer B
          Direct P2P

Control Plane
          Admin Authority
                 │
        ┌────────┼────────┐
        │        │        │
     Trust    Policy   Membership
```

Administrator tidak menjadi perantara chat maupun transfer file — this
is the one non-negotiable constraint on everything below. Every policy
check happens on peers that are already talking directly; the admin
never sits on the data path.

---

## 2. Tujuan Group

Group digunakan untuk lingkungan terkelola: perusahaan, sekolah,
laboratorium, organisasi, tim internal, deployment perangkat perusahaan.

Administrator memiliki kewenangan untuk mengatur perangkat yang berada
dalam group. Namun administrator bukan server — komunikasi antar-member
tetap dilakukan secara langsung (`Employee A ═══ Employee B`, bukan
`Employee A → Admin → Employee B`).

---

## 3. Admin sebagai Root Authority

Setiap group memiliki satu atau lebih administrator yang bertindak
sebagai Group Authority. Admin memiliki cryptographic identity sendiri
— **the same `core/identity/` Ed25519 machinery from Phase 3, not a
separate key type**, just a device whose public key is additionally
recorded as an admin for a given group.

```
Group
│
├── Group ID
├── Admin Public Key
├── Group Policy
└── Membership
    ├── Device A
    ├── Device B
    └── Device C
```

Admin menggunakan private key untuk menandatangani keputusan penting.
Private key administrator: tidak dikirim ke member, tidak digunakan
sebagai session encryption key, tidak digunakan untuk membaca traffic
P2P, tidak menjadi bagian dari jalur transfer data. Digunakan murni untuk
authority dan signatures — matches `SECURITY_MODEL.md` §2's boundary
between Identity/Transport/Authority exactly.

---

## 4. Membership

Perangkat yang bergabung ke group memperoleh membership yang
ditandatangani oleh administrator.

```
peerc Membership Certificate

Device ID:       <device-id>
Public Key:      <ed25519-public-key>
Group ID:        <group-id>
Role:            Employee
Permissions:     <permissions>
Issued At:       <timestamp>
Expires At:      <timestamp>

Admin Signature: <signature>
```

Member tidak cukup hanya mengatakan "I am a member of Company X." Peer
lain harus dapat memverifikasi:

```
Device Identity → Membership Certificate → Admin Signature → Valid?
```

---

## 5. Group Policy

Administrator dapat menentukan policy yang berlaku untuk seluruh group
atau kelompok tertentu.

```
allow_external_trust = false
allow_export = false
leave_requires_admin = true
allow_inter_group = false
```

**Policy harus ditegakkan pada core, bukan hanya pada UI**:

```
export()
    ↓
policy check
    ↓
DENIED
```

meskipun seseorang mencoba memanggil fungsi tersebut secara langsung —
matches the project's existing pattern exactly (`validate_message()`
lives in `core/protocol/`, not in the UI layer (`app/`); `KeyStore` and `TrustStore`
refuse invalid states at the core layer, not just at a UI prompt).

---

## 6. External Trust Restriction

Group dapat melarang member mempercayai perangkat yang bukan bagian dari
group.

```
Company Group
Laptop A       ✓
Laptop B       ✓
Phone C        ✓
Personal PC    ✗

Policy: allow_external_trust = false
```

Penolakan harus dilakukan oleh core — i.e., `TrustStore.record_first_seen()`
(Phase 4) must consult group policy before inserting a `PENDING` entry
for a device outside the group, when this policy is active.

---

## 7. Communication Policy

Administrator dapat membatasi peer mana yang boleh berkomunikasi.

```
Engineering → Engineering     ALLOW
Engineering → Management      ALLOW
Engineering → Finance         DENY
Engineering → HR              DENY
```

```
Source Device/Group → Destination Device/Group → Action → ALLOW/DENY
```

Action dapat meliputi: `CHAT`, `FILE_SEND`, `FILE_RECEIVE`, `EXPORT`,
`TRUST`, `GROUP_JOIN`, `GROUP_LEAVE`.

---

## 8. Multiple Groups

Satu perangkat dapat menjadi member beberapa group apabila policy
mengizinkannya. Membership pada satu group tidak otomatis memberikan
akses ke group lain. Administrator dapat menentukan apakah
`Group A ↔ Group B` diperbolehkan.

---

## 9. Group Join

```
Device → Join Request → Group Authority
                            ├── Approve → Membership Certificate
                            └── Reject
```

Membership diberikan setelah authority memvalidasi device.

---

## 10. Controlled Leave

Group dapat menetapkan `leave_requires_admin = true`.

```
Member → Leave Request → Admin
                            ├── APPROVE → Revocation
                            └── DENY
```

Jika disetujui: `Membership → REVOKED`.

**Catatan**: peerc tidak dapat secara absolut mencegah seseorang
mematikan perangkat, menghapus aplikasi, menghapus file lokal, atau
mengganti OS — kontrol tersebut berada di luar aplikasi dan membutuhkan
mekanisme OS/MDM jika diperlukan. peerc hanya dapat mengontrol
authorization di dalam ekosistem peerc — matches
`SECURITY_MODEL.md` §27's honesty about this limit exactly.

---

## 11. Export Authorization — integrated with personal Secure Storage

**This is the resolved integration question.** Two independent
mechanisms both gate Export, and **both are required when a device is in
a group with `allow_export` policy active — this is an AND, not a
choice of one or the other**:

```
Export requested
      │
      ▼
Is this device in a group?
      │
      ├── NO  → personal Secure Storage gate only
      │         (SECURE_STORAGE_DESIGN.md §4/§6/§11.7:
      │          passphrase, +critical-action key if configured)
      │
      └── YES → group policy check FIRST
                      │
                      ├── group requires ADMIN_APPROVAL for export?
                      │        │
                      │        ├── NO valid, unexpired, signature-
                      │        │    verified Export Authorization
                      │        │    for (device, file, action=EXPORT)
                      │        │    → DENY (fail-closed, §20 SECURITY_MODEL.md)
                      │        │
                      │        └── valid capability present
                      │                 │
                      │                 ▼
                      │        personal Secure Storage gate
                      │        (passphrase, +critical-action key)
                      │                 │
                      │                 ▼
                      │            BOTH passed → Export proceeds
                      │
                      └── policy doesn't require approval for this
                          action → personal Secure Storage gate only
```

Why AND and not OR: the group's admin-signed capability is an
**authorization** check ("is this device allowed to export this file at
all, per company policy") — a permission gate. The personal
passphrase/critical-action key is a **cryptographic** check (proof of
possession that actually unwraps the DEK, per `SECURE_STORAGE_DESIGN.md`
§2). These answer different questions and neither substitutes for the
other: a valid admin capability doesn't hand over anyone's personal DEK,
and knowing the personal passphrase doesn't grant company policy
permission. A managed device needs both; a personal (non-group) device
only ever needed the second one, unchanged from `SECURE_STORAGE_DESIGN.md`'s
original design — **Group Authority adds a gate on top of the existing
personal model, it does not replace or weaken it.**

```
Export Request

Request ID: <request-id>
Device ID:  <device-id>
Group ID:   <group-id>
File ID:    <file-id>
Action:     EXPORT
Timestamp:  <timestamp>
Reason:     <optional-reason>
```

File tidak perlu dikirim ke administrator. Admin hanya memberikan
authorization:

```
Export Authorization

Request ID: <request-id>
Device ID:  <device-id>
File ID:    <file-id>
Action:     EXPORT
Expires:    <short-expiration>

Admin Signature: <signature>
```

Device memverifikasi signature tersebut sebelum melakukan export.

---

## 12. Short-Lived Capability

Authorization export sebaiknya tidak bersifat permanen.

```
Request → Admin Approval → Capability
                              ├── Device = A
                              ├── File = X
                              ├── Action = EXPORT
                              ├── Expires = 5 minutes
                              └── Nonce = random
```

Capability hanya berlaku untuk device tertentu, file tertentu, action
tertentu, selama waktu tertentu. Setelah digunakan atau expired:
`Capability → INVALID`.

---

## 13. Audit Log

Tindakan administrator harus dapat dicatat.

```
2026-09-12 13:41  ADMIN  Approved EXPORT   Device: A  File: X
2026-09-12 13:52  ADMIN  Revoked DEVICE    Device: C
2026-09-12 14:01  ADMIN  Changed POLICY    external_trust = false
```

Event dapat diberi signature administrator. Audit log digunakan untuk
accountability, bukan untuk mengubah admin menjadi server komunikasi.
Implemented as part of Phase 41's Security Event Logging
(`SECURITY_MODEL.md` §29) with `severity=INFO`/`WARNING` typically for
routine admin actions, escalating per that classification when the
action itself is unusual (e.g. mass revocation).

---

## 14. Multiple Administrators

Untuk organisasi besar, group dapat mendukung lebih dari satu
administrator.

```
              Group Authority
                     │
          ┌──────────┼──────────┐
          │          │          │
        Admin A    Admin B    Admin C
```

Policy tertentu dapat menggunakan threshold approval:

```
Export Confidential Data
Requires: 2 of 3 administrators
    Admin A ✓
    Admin B ✓
    Admin C -
    Result: APPROVED
```

Ini dapat diimplementasikan menggunakan cryptographic signatures tanpa
blockchain — `k`-of-`n` signature verification against the group's
recorded admin public keys (`SECURITY_MODEL.md` §22).

---

## Security Boundary (summary)

Administrator memiliki authority terhadap: membership, trust policy,
permissions, export authorization, device revocation, group policy.

Administrator **tidak otomatis** memiliki kemampuan untuk: membaca E2E
encrypted chat, membaca E2E encrypted file, mendapatkan private key
member, mendekripsi session hanya karena menjadi admin.

```
Administrative Authority ≠ Decryption Authority
```

Keduanya harus dipisahkan secara eksplisit — enforced structurally by
§11's AND-gate design: the admin's signature only ever unlocks the
*policy* gate, never the cryptographic one.

---

## 15. Core Design Principles (carried over, unchanged)

```
Identity ≠ Locator          Public Key → Identity,  IP/Port → Locator
Admin ≠ Server               Admin → Authority,  Peers → Data communication
Discovery ≠ Trust            Found ≠ Trusted
Authorization ≠ Decryption   Admin approval ≠ ability to read E2E data
Direct First                 Direct P2P → Relay only if necessary
Cryptography First           All identity/authorization verifiable cryptographically
Policy Must Be Enforced by Core   Not just UI
```

## Target Behavior

```
Personal P2P:        Phone ═══ Laptop (no group authority)

Managed Organization:
                 Company Group
                       │
                    Admin
                       │
          ┌────────────┼────────────┐
          │            │            │
       Laptop A      Laptop B     Phone C
          ╲____________│____________╱
                  Direct P2P
```

Admin mengontrol membership, trust, permissions, export authorization,
communication policy, revocation — tetapi tidak menjadi jalur komunikasi.

«Direct communication. Cryptographic identity. Centralized authority.»
«Decentralized data plane, governed control plane.»

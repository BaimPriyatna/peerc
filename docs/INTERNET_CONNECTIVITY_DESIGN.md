# Internet P2P Connectivity

Status: **design, no code yet** — reference for Phase 44-46
(`IMPLEMENTATION_PLAN.md`). Adapted from the provided specification;
project name aligned to `peerc`. The Device Key Rotation integration
question is resolved explicitly (§Endpoint Update and Key Rotation) per
an explicit decision: **rotation matters especially here, since
Internet-facing devices need their contact path to stay valid without
manual re-adding** — the same continuity problem Endpoint Update already
solves for IP changes, extended to identity changes.

---

## 1. Identity vs Locator

peerc harus memisahkan identity dari location.

```
IDENTITY                          LOCATOR
Ed25519 Public Key                IP / IPv6
       │                          Port
       └── Device ID/Fingerprint  Network Interface
                                  Endpoint
```

IP bukan identity. Public key bukan alamat jaringan. **[Already the
project's model since Phase 3 — `device_id = SHA256(public_key)`,
completely independent of `discovery.py`'s locator handling.]**

---

## 2. Device Identity (unchanged from Phase 3)

```
Ed25519 Keypair
│
├── Private Key → stays on device
│
└── Public Key → Device ID → SHA-256(Public Key)
```

Device ID tetap sama walaupun IP berubah, Wi-Fi berubah, router berubah,
DHCP memberikan IP baru, atau perangkat berpindah jaringan — **as long as
the key itself hasn't rotated. See §Endpoint Update and Key Rotation
below for what happens when it does.**

---

## 3. Locator

Satu device dapat memiliki beberapa endpoint.

```
Device A
Identity:  Device ID = ABC123
Endpoints: 192.168.1.20:5656
           10.10.0.20:5656
           [IPv6]:5656
           45.x.x.x:5656
```

Endpoint hanya digunakan untuk mencoba menemukan jalur komunikasi.

---

## 3a. Link Format (Add-by-Link)

Cara manual untuk menambahkan peer via internet, tanpa bergantung pada
Rendezvous (Phase 45) sudah berjalan — dikirim lewat jalur apa pun yang
sudah dipercaya (WhatsApp, email, dll). Keputusan final dari diskusi:

**Bentuk**: string yang bisa di-copy-paste, dilindungi PIN 6 digit
(bukan QR-only) — QR adalah cara render tambahan dari string yang sama,
bukan encoding terpisah.

```
PEERC1:<base64url(salt || nonce || ciphertext)>
```

| # | Field | Lokasi | Ukuran | Keterangan |
|---|---|---|---|---|
| 1 | `PEERC1:` | plaintext (prefix) | 7 char | Penanda versi format; dicek sebelum parse base64 |
| 2 | `salt` | plaintext | 16 byte | Input Scrypt(PIN, salt) → KEK. Wajib random per-link — PIN 6 digit cuma 1 juta kemungkinan; salt tetap/predictable = precompute sekali, bobol semua link selamanya |
| 3 | `nonce` | plaintext | 12 byte | Nonce AES-256-GCM (standar AEAD, publik) |
| 4 | `public_key` | **terenkripsi** | 32 byte | Ed25519 public key pengirim; `device_id` diturunkan dari ini setelah verifikasi (bukan disimpan terpisah) |
| 5 | `endpoints[]` | **terenkripsi** | ~14-40 byte | Tagged `direct-v4` / `direct-v6` / `rendezvous`; boleh lebih dari satu sekaligus — direct dicoba dulu (cepat), rendezvous jadi fallback kalau direct gagal (reuse pola §11 Try Direct → Relay, diterapkan di level endpoint resolution) |
| 6 | `created_at` | **terenkripsi** | 4 byte | Informasional untuk UI ("link dibuat 3 hari lalu") — bukan expiry |
| 7 | `signature` | **terenkripsi** | 64 byte | Ed25519 signature atas field 4-6, ditandatangani device pengirim |
| — | GCM tag | menempel di akhir ciphertext | 16 byte | Auth tag AES-256-GCM |

Total mentah ±169 byte → **±233 karakter** (prefix + base64url).

**Urutan kriptografi: Sign-then-Encrypt** (payload ditandatangani dulu,
baru seluruh hasil dienkripsi) — bukan Encrypt-then-Sign. Alasan:
- Tanpa PIN, penyerang tidak bisa melihat apa pun (device_id, endpoint,
  signature) — Encrypt-then-Sign mengharuskan `public_key` bocor di luar
  enkripsi supaya signature bisa diverifikasi tanpa PIN, yang justru
  membocorkan identitas device ke siapa pun yang sekadar melihat link.
- AES-GCM sudah menjamin integritas ciphertext duluan (tamper = gagal
  decrypt) sebelum signature sempat diperiksa.
- Signature baru benar-benar berguna di skenario **PIN berhasil
  ditebak/dibrute-force** (realistis untuk ruang 6 digit meski
  diperlambat Scrypt) — tanpa signature, penyerang yang sudah pegang PIN
  bisa membuat link palsu (public_key & endpoint miliknya sendiri) yang
  terlihat 100% sah. Dengan signature, link palsu itu tetap gagal
  verifikasi karena penyerang tidak punya private key aslinya.

**Expiry**: sengaja tidak ada. Link tetap valid selama endpoint belum
berubah; begitu berubah, mekanisme Endpoint Update (§4, signed
announcement) otomatis memperbaruinya tanpa perlu link baru — asal
minimal satu kontak berhasil terjadi sebelum kedua sisi sama-sama
offline dan berganti IP bersamaan (§8, satu-satunya kondisi yang
membuat link benar-benar basi).

**Approval**: link bukan kunci masuk otomatis. Setelah koneksi berhasil
(endpoint ditemukan + identity terverifikasi via signature link ini +
handshake Phase 6), approval tetap manual di sisi pemilik link — link
hanya menyelesaikan masalah *penemuan + pembuktian identitas*, bukan
trust.

**Alternatif yang dipertimbangkan dan ditolak**:
- Target 64 karakter tanpa mengurangi informasi — **tidak memungkinkan**
  secara matematis. Signature Ed25519 (64 byte) sendirian sudah melebihi
  budget 48 byte yang tersedia di 64 karakter base64. Versi paling
  kompak yang masih menyertakan signature penuh (salt+nonce digabung
  jadi satu blok dual-purpose, endpoint tanpa port kalau pakai default,
  tanpa `created_at`) mentok di ±184 karakter, bukan 64.
  Skema signature lebih pendek (mis. BLS, ~48 byte via pairing curve)
  ditolak karena menambah dependency kripto baru di luar stack yang
  sudah dipakai project ini (Ed25519/X25519/ChaCha20-Poly1305 via
  `cryptography`), untuk penghematan yang tidak signifikan.
- 64 karakter tanpa signature — ditolak. Selisih 64 vs ±233 karakter
  tidak berdampak nyata ke UX (link dipakai lewat copy-paste, bukan
  diketik manual — yang diketik manual cuma PIN 6 digit), sementara
  signature adalah satu-satunya pengaman yang tersisa jika PIN berhasil
  dibobol.

**QR code**: hanya sebagai cara render tambahan dari string di atas,
bukan encoding terpisah.
- **Generate** (wajib): ASCII/ANSI QR langsung di terminal (library
  `qrcode`), dan/atau export ke file `.png` untuk dikirim lewat
  WA/email. String tidak lolos QR Alphanumeric mode (base64url pakai
  huruf kecil) — pakai Byte mode, butuh QR version ±10-12, masih mudah
  di-scan kamera HP biasa.
- **Decode** (nice-to-have, belum diprioritaskan): dari file gambar
  (`pyzbar`, tanpa kamera aktif) — bukan live scanning.
- **Live camera scan via web** (dipertimbangkan, ditolak untuk
  sekarang): ide-nya peerc buka HTTP server LAN sementara + halaman
  browser HP untuk scan kamera lalu POST hasilnya balik ke peerc.
  Blocker nyata: browser modern menolak akses kamera (`getUserMedia`)
  di luar HTTPS/localhost — `http://<lan-ip>:<port>/...` akan ditolak,
  butuh sertifikat TLS (self-signed = warning "Not Secure" di HP orang)
  untuk UX yang justru ingin dibikin mulus. Dicatat sebagai ide masa
  depan **kalau/ketika ada aplikasi GUI** (bukan TUI) — di situ live
  camera scan native jauh lebih masuk akal daripada lewat browser.

---

## 4. Endpoint Update

Ketika IP berubah:

```
OLD 45.10.10.20:5656 → IP change → NEW 103.20.30.40:5656
```

Device membuat endpoint announcement yang ditandatangani:

```
Endpoint Update

Device ID: <device-id>
Endpoint:  103.20.30.40:5656
Timestamp: <timestamp>
Nonce:     <random>
Signature: <Ed25519 signature>
```

Peer penerima:

```
Receive → Verify signature → Public key matches known identity? →
Timestamp valid? → Nonce valid? → Update endpoint
```

Peer lain tidak cukup hanya mengklaim "Device A sekarang berada di IP
X." — harus dibuktikan dengan signature dari identity Device A. Reuses
Phase 6's existing signature-verification machinery
(`compute_initiator_transcript`-style signing, `NonceCache` for
replay protection) rather than inventing new primitives.

---

## Endpoint Update and Key Rotation — the resolved integration

**Both mechanisms solve the same underlying problem: "how does a peer
keep trusting the same logical device across a change, without a human
having to manually re-approve it every time?"** — just for two different
kinds of change:

```
                    "Same device, something changed"
                                │
              ┌─────────────────┴─────────────────┐
              │                                   │
      Locator changed                     Identity key changed
     (IP/port — Endpoint Update)         (device_id itself — Key Rotation,
              │                           SECURITY_MODEL.md §15, Phase 40)
              │                                   │
      Signed by the SAME,                Signed by the OLD key
      unchanged identity key             (Transition Certificate: old
      (device_id unaffected —            key signs new key), because
      trivial case, peer already          device_id = SHA256(pubkey)
      recognizes this device_id)          DOES change here
              │                                   │
              ▼                                   ▼
      Peer updates locator                Peer's TrustStore verifies the
      for the known device_id             transition cert, then carries
      it already trusts.                  TRUSTED status forward to the
                                           NEW device_id automatically.
                                           No fresh TOFU approval needed.
```

Why this matters **especially** for Internet (non-local) connections,
as opposed to LAN: on a LAN, re-discovering and re-approving a device
that changed is low-friction (it's physically nearby, TOFU re-approval
is a minor interruption). Over the Internet, a device might be a laptop
that only reconnects occasionally from different networks/IPs, or an
org's fleet of devices undergoing routine scheduled key rotation
(`SECURITY_MODEL.md` §15's stated rotation triggers) — requiring a human
to manually re-approve trust every single time either the IP OR the key
changed would make the system practically unusable at any real scale.
Both Endpoint Update and Key Rotation exist specifically to keep the
contact path (locator) and the trust relationship (identity) valid
without repeated manual re-adding, using the same underlying pattern
(a signature the receiving peer can independently verify, not a claim it
has to just believe).

A compromise-triggered rotation (`SECURITY_MODEL.md` §16) deliberately
does **not** get this auto-continuity — there's no transition
certificate from a key that's been compromised, so peers correctly fall
back to treating it as a brand-new, unverified identity requiring fresh
TOFU. Continuity is only automatic for a *planned*, signed transition.

---

## 5. Public Key dan Key Exchange

Public key identity tidak digunakan sebagai satu-satunya session key.

```
Long-term Identity → Ed25519 → identity + signatures
Ephemeral Session   → X25519 → key exchange → HKDF → session keys
```

Kemudian session digunakan untuk AEAD: ChaCha20-Poly1305. **[Phase 6-8,
implemented — this section describes exactly what's already built.]**

---

## 6. Connection Flow

```
Peer B → Known endpoint A? → YES → Connect IP:Port → Handshake
                                        ├── Protocol version
                                        ├── Device identity
                                        ├── Ephemeral X25519 key
                                        ├── Nonce
                                        └── Signatures
                                        ▼
                              Verify Ed25519 identity
                                        ▼
                              X25519 key exchange
                                        ▼
                              HKDF key derivation
                                        ▼
                              Encrypted session
```

**[Phase 6-9, implemented — matches `core/crypto/handshake.py`'s
`perform_handshake_initiator`/`perform_handshake_responder` flow
exactly.]**

---

## 7. IP Change Problem

Jika hanya satu peer berganti IP ketika peer lain sedang online:

```
A: Old IP → New IP → Endpoint Update → B receives update
```

Masalah dapat diselesaikan karena setidaknya satu jalur komunikasi masih
tersedia.

---

## 8. Simultaneous Offline IP Change

Pure P2P memiliki batasan fundamental.

```
Before: A(1.1.1.1) ←──→ B(2.2.2.2)

Both go OFFLINE, both change IP:
  A → 9.9.9.9
  B → 8.8.8.8

When both come back online: A doesn't know B's new locator,
B doesn't know A's new locator. Neither party knows the change happened.
```

**Kesimpulan**: Pure P2P tidak dapat menjamin discovery dalam kondisi
kedua peer offline dan keduanya sekaligus kehilangan locator lama. Ini
merupakan **keterbatasan informasi, bukan bug implementasi** — already
listed as a non-guarantee in `SECURITY_MODEL.md` §32.

---

## 9. Rendezvous untuk Internet

Untuk mengatasi masalah discovery Internet, peerc dapat menyediakan
optional Rendezvous Service (Phase 45). **Rendezvous bukan data server.**

```
                  Rendezvous
                 /           \
                A             B
                 \           /
                  ═══════════
                    DIRECT
                      P2P
```

Rendezvous hanya membantu: menemukan endpoint, memperbarui locator,
koordinasi NAT traversal, menyediakan informasi candidate endpoint.
Traffic chat/file tetap `A ═══ B` (E2E encrypted), bukan
`A → Rendezvous → B`.

---

## 10. Self-Hosted Rendezvous

Untuk perusahaan atau organisasi, rendezvous dapat di-host sendiri, dan
dipisahkan dari Group Authority — satu server tidak harus melakukan
semua fungsi:

```
Company
│
└── peerc Rendezvous
        ├── Laptop A
        ├── Laptop B
        └── Phone C

Group Authority → membership / policy   (GROUP_AUTHORITY_DESIGN.md, Phase 42)
Rendezvous       → endpoint discovery   (this document, Phase 45)
```

---

## 11. Optional Relay

Jika direct P2P gagal karena NAT, firewall, carrier-grade NAT, atau
restrictive network — Phase 46:

```
Try Direct → SUCCESS → Direct P2P
           → FAIL     → Relay
```

Relay hanya menjadi transport. Payload tetap E2E encrypted — relay
tidak memperoleh session plaintext.

---

## 12. Local Network Discovery (existing, Phase 5 — Discovery V2)

```
Local Discovery
├── UDP Broadcast   [already implemented, discovery.py]
├── mDNS
├── Interface Discovery
├── Known Endpoints
└── Manual Endpoint  [already implemented — IPv6 connect included]
```

Local discovery tidak boleh bergantung hanya pada satu subnet.

---

## 13. Multiple Local Interfaces / Multi-Subnet Discovery

```
wlan0  192.168.1.20/24
eth0   192.168.2.20/24
vpn0   10.10.0.20/16
```

Broadcast pada satu subnet tidak otomatis mencapai subnet lain. peerc
perlu memanfaatkan mDNS jika tersedia, routing information, known
endpoints, configured discovery networks, rendezvous/VPN ketika jaringan
terpisah, dan optional controlled subnet scanning.

---

## 14. Local Scan Policy

"Scan seluruh jaringan lokal" tidak berarti peerc harus membabi buta
melakukan scan seluruh address space.

```
Network Interfaces → Routing Table → Reachable Networks → Discovery Strategy
```

Discovery harus dibatasi agar tidak menyebabkan excessive network
traffic, device overload, accidental network scanning, firewall alerts,
atau unnecessary battery usage.

---

## 15. Discovery ≠ Trust

Perangkat yang ditemukan tidak otomatis dipercaya.

```
DISCOVERY            "Ada peerc di sini."
      ↓
IDENTITY VERIFICATION "Siapa kamu?"
      ↓
AUTHENTICATION        "Buktikan private key."
      ↓
TRUST / MEMBERSHIP    "Apakah policy mengizinkan?"
      ↓
CONNECTION
```

Discovery hanya menemukan locator. **[Phase 4's TOFU already implements
exactly this separation for the local-discovery case; this generalizes
it to the Internet-discovery case too.]**

---

## Final Connectivity Architecture

```
                         peerc
                           │
              ┌────────────┴────────────┐
              │                         │
        LOCAL DISCOVERY           INTERNET DISCOVERY
              │                         │
      ┌───────┼────────┐                │
      │       │        │           Rendezvous
 Broadcast  mDNS   Interface             │
      │       │    Discovery             │
      └───────┼────────┘                 │
              │                          │
              └──────────┬───────────────┘
                         ▼
                 Endpoint Candidates
                         │
                         ▼
                  Identity Verify
                         │
                         ▼
                   Authentication
                         │
                         ▼
                   NAT Traversal
                         │
                  ┌──────┴──────┐
                  │             │
               Direct          Relay
                  │             │
                  └──────┬──────┘
                         ▼
                  Encrypted Session
                         │
              ┌──────────┼──────────┐
              │          │          │
             Chat       Files      Media
```

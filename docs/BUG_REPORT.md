# Bug Report — peerc

> Disesuaikan dari laporan audit sebelumnya (saat proyek masih bernama
> `peerc`). Perubahan di versi ini:
> 1. Semua penyebutan proyek diganti ke **peerc**.
> 2. Status bug yang sudah diperbaiki pada patch upgrade-prep ditandai ✅.
> 3. Bagian device identity (BUG-003) diperjelas dengan hasil diskusi:
>    **IP, MAC address, dan hostname sudah final ditolak** sebagai basis
>    device identity — lihat catatan di bawah BUG-003.

## Ringkasan

Severity	Jumlah	Fokus

🔴 Critical	5	Security, remote file write, DoS
🟠 High	8	Protocol, transfer reliability, connection
🟡 Medium	9	UI, discovery, robustness
🟢 Low	4	UX/maintainability
🏗 Architecture	3	Technical debt

Total: 29 issue.

> Catatan: beberapa di bawah adalah design/security weaknesses, bukan crash
> bug murni. Saya tetap masukkan karena untuk aplikasi P2P yang menerima
> koneksi dari network, itu harus dianggap sebagai bug sebelum v1.0.

### Status ringkas (setelah patch upgrade-prep)

| Bug | Status |
|---|---|
| BUG-001 Path traversal | ✅ Fixed — `_safe_dest_path()` di `file_transfer.py` |
| BUG-002 File size DoS | ✅ Fixed — `MAX_INCOMING_FILE_SIZE` + per-chunk enforcement |
| BUG-003 Identity masih UUID | ⏳ Belum — keputusan desain sudah final (Ed25519), implementasi belum jalan |
| BUG-004 TCP plaintext | ✅ Fixed (v1.15.1) — ConnectionManager wired to core/transport's authenticated handshake + ChaCha20-Poly1305 |
| BUG-005 Unauthenticated hello | ⏳ Belum — bagian dari BUG-003 |
| BUG-006 Frame limit 100 MB | 🟡 Partial — limit khusus untuk `chat` sudah ada (64 KB); binary framing untuk file belum |
| BUG-007 Base64 file transfer | ⏳ Belum |
| BUG-008 Chunk index tidak diverifikasi | ✅ Fixed |
| BUG-009 `is_last` tidak diverifikasi | ✅ Fixed |
| BUG-010 Checksum dari `file_done` dipercaya | ✅ Fixed — `file_offer` checksum jadi authoritative |
| BUG-011 Sender identity kosong | ⏳ Belum — butuh authenticated session (Phase 6) |
| BUG-012 Sender anggap transfer selesai terlalu cepat | ✅ Fixed — `file_complete_ack` |
| BUG-013 `offer_file()` tidak cek hasil `send()` | ✅ Fixed |
| BUG-014 Tidak ada connect/handshake timeout | 🟡 Partial — TCP connect timeout sudah; handshake (`hello`) timeout belum |
| BUG-015 Duplicate connections | ⏳ Belum — butuh `device_id`, bukan `ip:port` |
| BUG-016 Tidak ada connection limit | ✅ Fixed — `MAX_CONNECTIONS` |
| BUG-017 Malformed JSON belum schema-safe | ✅ Fixed — `protocol.validate_message()` |
| BUG-018 message tidak dijamin dict | ✅ Fixed |
| BUG-019 Rich markup injection | ✅ Fixed — `rich.markup.escape()` |
| BUG-020 Nickname tidak dibatasi | ✅ Fixed |
| BUG-021 Chat message tanpa size limit | ✅ Fixed — `MAX_CHAT_TEXT_SIZE` |
| BUG-022 ACK race condition | ✅ Fixed — pending diregister sebelum `send()` |
| BUG-023 Discovery packet tidak divalidasi | ✅ Fixed |
| BUG-024 Multi-subnet | ⏳ Belum (bukan security bug, backlog) |
| BUG-025 IPv6 `/connect` tidak didukung | ✅ Fixed |
| BUG-026 Manual peer placeholder identity palsu | ⏳ Belum — butuh Phase 3/6 |
| BUG-027 Discovery jalankan `ip` command tiap 3 detik | ⏳ Belum |
| BUG-028 Private identity file belum diamankan | ⏳ Belum — relevan begitu Phase 3 jalan |
| BUG-029 Test suite belum full automated | 🟡 Partial — `test_security_fixes.py` dan `test_upgrade_fixes.py` sudah ditambahkan, coverage belum lengkap |

---

## 🔴 P0 — Critical

### BUG-001 — Path Traversal pada Incoming Filename ✅ Fixed

File: `file_transfer.py`
Severity: 🔴 Critical

~~Masih belum diperbaiki.~~ **Sudah diperbaiki.** Receiver sekarang melalui
`_safe_dest_path()`: strip ke basename, resolve destination, lalu verifikasi
hasil resolve masih di dalam `downloads_dir` sebelum file handle dibuka.

```
sanitize filename
    ↓
resolve destination
    ↓
verify destination is inside downloads_dir
```

Ditest di `test_security_fixes.py::test_path_traversal`.

---

### BUG-002 — File Size Tidak Dibatasi Saat Receiving ✅ Fixed

File: `file_transfer.py`
Severity: 🔴 Critical

Sekarang ada `MAX_INCOMING_FILE_SIZE` (2 GB) yang menolak offer yang sudah
kelewat besar sebelum diterima, ditambah pengecekan per-chunk:

```python
if transfer.bytes_received + len(data) > transfer.size:
    abort_transfer()
```

Ditest di `test_security_fixes.py::test_oversized_declared_then_overflow_chunk`.

---

### BUG-003 — Device Identity Masih UUID, Bukan Cryptographic Identity ⏳ Belum diimplementasikan

File: `discovery.py`
Severity: 🔴 Critical

Repo sekarang memang memiliki stable peer ID, tetapi itu masih UUID yang
disimpan di `.peerc_identity.json`.

Artinya:

```
peer_id = UUID
```

belum berarti:

```
peer_id = proof of identity
```

Attacker dapat mengklaim:

```
peer_id = DEVICE_A
name = "Laptop A"
```

karena tidak ada signature yang membuktikan kepemilikan identity.

Handshake sekarang juga hanya mengirim:

```
peer_id
sender_name
tcp_port
timestamp
```

tanpa cryptographic authentication.

**Keputusan desain (final, hasil diskusi):** identity berbasis Ed25519
keypair, **bukan** apa pun yang terikat jaringan atau hardware. Alasan
setiap alternatif ditolak:

| Kandidat | Kenapa ditolak |
|---|---|
| IP address | Berubah-ubah (DHCP, ganti jaringan) |
| MAC address | Di-randomize per-network oleh kebanyakan OS modern (privacy) |
| Hostname | User bisa ganti kapan saja; dua device bisa punya hostname sama |
| UUID acak (status sekarang) | Tidak berubah, tapi **tidak bisa dibuktikan** — siapa pun bisa klaim UUID orang lain |
| Hardware serial / machine-id | Tidak portable cross-platform (beda API tiap OS), privacy-invasive (identifier fisik permanen bocor ke peer lain) |
| TPM / Secure Enclave | Paling kuat secara teori, tapi tidak semua device punya akses; jadi **tempat penyimpanan** private key di masa depan, bukan pengganti konsep Ed25519 |

Fix:

```
Ed25519 public key
        ↓
device_id = SHA256(public_key)
        ↓
signature
```

`device_id` "tidak berubah" bukan karena terikat hardware, tapi karena device
memilih untuk terus memakai key yang sama — dan karena ada private key di
baliknya, kepemilikannya bisa **dibuktikan** ke peer lain lewat signature.
Detail implementasi ada di `Implementation_plan.md` Phase 3.

---

### BUG-004 — TCP Masih Plaintext ✅ Fixed (v1.15.1)

File: `peer.py`, `protocol.py`
Severity: 🔴 Critical

Repo sendiri masih mencatat bahwa komunikasi belum E2E encrypted dan masih
menggunakan plain TCP.

```
Chat
File
Metadata
   ↓
TCP plaintext
```

Siapa pun yang dapat sniff LAN berpotensi membaca traffic.

Fix (Phase 6–9 di implementation plan):

```
Ed25519
    ↓
authenticated handshake
    ↓
X25519
    ↓
HKDF
    ↓
ChaCha20-Poly1305
    ↓
encrypted session
```

**Status:** Phase 6–9 sudah diimplementasikan dan diuji standalone sejak
lama, tapi ternyata tidak pernah benar-benar disambungkan ke
`ConnectionManager` yang jalan di app — celah ini baru ketahuan saat
mengerjakan Phase 39.2 (persistence butuh device_id yang benar-benar
terautentikasi, bukan sekadar field self-reported). `peer.py` sekarang
memakai `core/transport`'s `initiate_secure_session`/`accept_secure_session`
untuk setiap koneksi, masuk maupun keluar. `TrustStore` (Phase 4) ikut
disambung live untuk pertama kalinya sekaligus (masih pakai `trust.db`
plaintext-nya sendiri untuk saat ini — migrasi ke vault terenkripsi
menyusul di Phase 39.2).

---

### BUG-005 — Unauthenticated `hello` Dapat Memanipulasi Peer Registry ✅ Fixed (v1.15.1)

File: `ui.py`
Severity: 🔴 Critical

`_dispatch_handshake()` menerima `peer_id`, `sender_name`, `tcp_port` dari
remote dan langsung `registry.upsert(...)` tanpa membuktikan bahwa peer
tersebut benar-benar memiliki identity tersebut.

Bagian dari BUG-003 — akan tertutup sekaligus begitu authenticated handshake
(Phase 6) jalan.

**Status:** Tertutup bersamaan dengan BUG-004. `ui.py` sekarang
cross-check setiap `peer_id` self-reported di pesan `hello`/`hello_ack`/
`chat` terhadap `manager.get_peer_device_id(addr_key)` — identity yang
sudah dibuktikan lewat handshake — sebelum menulisnya ke peer registry.
Klaim yang tidak cocok ditolak dan dicatat sebagai peringatan keamanan
di log, bukan langsung dipercaya.

---

## 🟠 P1 — High

### BUG-006 — Frame Limit 100 MB Masih Terlalu Besar 🟡 Partial

File: `protocol.py`

`MAX_MESSAGE_SIZE = 100 * 1024 * 1024` masih berlaku secara global untuk
frame length-prefix. Yang sudah diperbaiki: pesan `chat` sekarang punya batas
sendiri (`MAX_CHAT_TEXT_SIZE = 64 KB`, lihat BUG-021) yang divalidasi di
`validate_message()`. Yang belum: `file_chunk` masih lewat frame JSON yang
sama, jadi limit 100 MB secara teknis masih ada di jalur itu sampai binary
framing (Phase 1.3 / BUG-007) selesai.

Target akhir:

```
CONTROL_FRAME_LIMIT
CHAT_FRAME_LIMIT
FILE_FRAME_LIMIT
```

Dan file sebaiknya tidak lagi menggunakan JSON frame sama sekali.

---

### BUG-007 — Base64 File Transfer ⏳ Belum

File: `file_transfer.py`

Masih menggunakan:

```
binary
 ↓
Base64
 ↓
JSON
 ↓
TCP
```

Overhead ~33% masih ada. Fix: `control → JSON`, `data → binary frame`
(Phase 1.3 / Phase 12 di implementation plan).

---

### BUG-008 — Chunk Index Tidak Diverifikasi ✅ Fixed

Receiver sekarang men-track `expected_chunk_index` dan menolak (abort) chunk
apa pun yang datang out-of-order:

```python
if chunk_index != transfer.expected_chunk_index:
    abort_transfer()
```

Ditest di `test_security_fixes.py::test_chunk_index_reorder_rejected`.

---

### BUG-009 — `is_last` Tidak Diverifikasi ✅ Fixed

`is_last=True` yang datang sebelum `bytes_received == size` sekarang ditolak,
bukan diterima begitu saja tanpa validasi.

---

### BUG-010 — Checksum dari `file_done` Dipercaya ✅ Fixed

Receiver sekarang hanya percaya checksum dari `file_offer`
(`transfer.expected_checksum`), field `checksum` di `file_done` tidak lagi
bisa menggantikannya.

Ditest di `test_security_fixes.py::test_file_done_checksum_cannot_override_offer`.

---

### BUG-011 — Sender Identity File Offer Kosong ⏳ Belum

Masih ada `sender_id=""`, `sender_name=""` pada `offer_file()`. Perbaikan
sebenarnya butuh identity yang berasal dari authenticated session
(Phase 6/ARCH-002), bukan sekadar isi manual — jadi ditahan sampai Phase 3/6
selesai.

---

### BUG-012 — Sender Menganggap Transfer Selesai Terlalu Cepat ✅ Fixed

Ditambahkan pesan `file_complete_ack`. Sender sekarang menunggu (timeout 30s)
sampai receiver selesai verifikasi checksum sebelum menandai transfer
"done":

```
FILE_DONE
      ↓
receiver verifies
      ↓
FILE_COMPLETE_ACK
      ↓
sender = completed
```

---

### BUG-013 — `offer_file()` Tidak Memeriksa Hasil `send()` ✅ Fixed

`offer_file()` sekarang mengembalikan `None` (bukan pretend-success) kalau
`send()` gagal — `ui.py` sudah disesuaikan untuk menangani kasus ini.

---

## 🟠 Connection Bugs

### BUG-014 — Tidak Ada Connect/Handshake Timeout 🟡 Partial

`connect_to()` sekarang dibungkus `asyncio.wait_for(CONNECT_TIMEOUT=5s)` —
bagian TCP connect sudah aman dari hang selamanya. Yang belum: timeout
khusus untuk `hello`/`hello_ack` (butuh connection state machine, Phase 33
di implementation plan) — sebuah koneksi yang berhasil TCP connect tapi
tidak pernah mengirim `hello` masih bisa menggantung tanpa batas waktu.

Ditest di `test_upgrade_fixes.py::test_connect_timeout`.

---

### BUG-015 — Duplicate Connections Masih Bisa Terjadi ⏳ Belum

Connection manager masih menggunakan `addr_key = ip:port`. Fix sebenarnya
(`device_id → canonical connection`) butuh identity Phase 3 selesai dulu —
tidak bisa di-patch terpisah.

---

### BUG-016 — Tidak Ada Connection Limit ✅ Fixed

`ConnectionManager` sekarang menerima `max_connections` (default 64).
Koneksi masuk yang melebihi limit langsung ditutup; koneksi keluar yang
melebihi limit melempar `ConnectionLimitError`.

Ditest di `test_upgrade_fixes.py::test_connection_limit`.

---

### BUG-017 — Malformed JSON/Protocol Handling Belum Schema-Safe ✅ Fixed

`protocol.validate_message()` sekarang mengecek field wajib per tipe pesan
sebelum dispatch, dipanggil dari `peer.py`'s read loop. Pesan yang tidak
lengkap membuat koneksi di-drop dengan bersih (`ProtocolError`), bukan
`KeyError` yang tidak tertangkap.

---

### BUG-018 — `message` Tidak Dijamin Berupa Dictionary ✅ Fixed

`validate_message()` mengecek `isinstance(message, dict)` di awal, sebelum
field apa pun diakses.

---

## 🟡 P2 — Medium

### BUG-019 — Rich Markup Injection pada Chat ✅ Fixed

Semua string dari remote (`sender_name`, `text`, nama file pada file offer)
sekarang di-escape lewat `rich.markup.escape()` sebelum masuk ke `RichLog`.

---

### BUG-020 — Nickname Tidak Dibatasi ✅ Fixed

`/nick` sekarang menolak control character/newline dan membatasi panjang
maksimal 32 karakter.

---

### BUG-021 — Chat Message Tidak Memiliki Size Limit Khusus ✅ Fixed

`MAX_CHAT_TEXT_SIZE = 64 KB` ditambahkan, divalidasi di dua sisi: client
(`chat.py::send_chat`, gagal cepat tanpa perlu network round-trip) dan
receiver (`protocol.validate_message`).

---

### BUG-022 — ACK Race Condition Masih Ada ✅ Fixed

`send_chat()` sekarang mendaftarkan pending/timeout state **sebelum**
memanggil `send()`, bukan sesudahnya — menutup celah race pada koneksi
lokal/cepat.

---

### BUG-023 — Discovery Packet Tidak Divalidasi dengan Baik ✅ Fixed

`_handle_packet()` sekarang memvalidasi tipe (`peer_id` harus string
non-kosong, `tcp_port` harus dalam rentang valid) sebelum masuk ke registry.

---

### BUG-024 — Discovery Tetap Tidak Menyelesaikan Multi-Subnet ⏳ Belum

Bukan security bug — tetap masuk backlog (Phase 5 di implementation plan,
kombinasi UDP broadcast + mDNS + manual `/connect`).

---

### BUG-025 — `/connect` IPv6 Tidak Didukung dengan Benar ✅ Fixed

Parser sekarang mendukung notasi bracket `[addr]:port` dan literal IPv6
mentah (2+ titik dua) tanpa salah parse sebagai `ip:port`.

Ditest di `test_upgrade_fixes.py::test_ipv6_connect_parsing`.

---

### BUG-026 — Manual Peer Placeholder Bisa Menjadi Identity Palsu di UI ⏳ Belum

`manual_id = f"peer-{ip}"` masih mencampurkan temporary address identity
dengan real device identity. Harus dihapus begitu Phase 3/6 (crypto
identity) selesai.

---

## 🟢 P3 — Low

### BUG-027 — Discovery Menjalankan `ip` Command Setiap Announcement ⏳ Belum

Tidak fatal, tetap backlog. Fix: cache network topology, refresh saat
interface berubah.

---

### BUG-028 — Private Identity File Belum Diamankan ⏳ Belum

Saat ini identity disimpan sebagai JSON biasa (`.peerc_identity.json`).
Belum jadi private-key leak karena belum ada private key — tapi begitu
Ed25519 (Phase 3) ditambahkan, desain ini **tidak boleh** diteruskan; private
key harus masuk secure keystore (lihat `KeyStore` abstraction di
implementation plan Phase 3.3).

---

### BUG-029 — Test Suite Belum Menjadi Automated Test Suite Sebenarnya 🟡 Partial

`test_stage2.py`–`test_stage5.py` masih manual/executable verification
scripts seperti sebelumnya. Yang baru ditambahkan: `test_security_fixes.py`
(path traversal, oversized chunk, chunk reorder, checksum authority,
malformed/non-dict JSON) dan `test_upgrade_fixes.py` (connect timeout,
connection limit, discovery validation, chat size limit, ACK race, IPv6
parsing). Belum ada coverage untuk: spoofed identity, MITM, revoked device
— karena fitur-fitur itu sendiri belum ada (Phase 3–9).

---

## 🏗 Architectural Issues

Belum berubah dari laporan sebelumnya — masih backlog.

### ARCH-001 — `on_message` Handler Chaining [RESOLVED in v1.14.0 / Phase 26]

```
ConnectionManager
       ↓
ChatSession
       ↓
FileTransferSession
       ↓
UI handshake
```

masing-masing melakukan `manager.on_message = ...` dan menyimpan callback
sebelumnya. **Selesai di Phase 26 (v1.14.0)**: Digantikan oleh `EventBus` (`core/events.py`)
dengan typed events (`NetworkMessageReceived`, `ChatReceived`, `FileOffered`, dll.).
Chaining `on_message` dihapus sepenuhnya.

### ARCH-002 — Identity Masih Berasal dari Payload [RESOLVED in v1.15.1 / BUG-004]

Chat handler mengambil `sender_id`/`sender_name` dari `message` dan bahkan
memasukkannya ke registry. Target: identity dari `session.device_id`
(authenticated), bukan dari payload yang bisa dipalsukan.

**Selesai bersamaan dengan BUG-004/BUG-005**: `ui.py` sekarang cross-check
`peer_id`/`sender_id` self-reported di `hello`/`hello_ack`/`chat` terhadap
`manager.get_peer_device_id(addr_key)` (`_verify_self_reported_id()`)
sebelum menulis ke registry.

### ARCH-003 — UI Masih Terlalu Menjadi Orchestrator

`ui.py` sekarang 600+ lines dan menangani Textual UI, discovery, TCP setup,
handshake, chat, file transfer, clipboard, command parsing, network
diagnostics, dan peer registry interaction sekaligus. Untuk prototype masih
masuk akal, tapi untuk roadmap ke depan perlu dipisah (Phase 26–27).

---

## Prioritas pengerjaan sekarang

```
P0 (sisa)
├── BUG-003/005 Identity authentication (Ed25519 — keputusan sudah final)
└── BUG-004 Encryption

P1 (sisa)
├── BUG-006/007 Binary protocol untuk file transfer
├── BUG-011 Sender identity dari authenticated session
├── BUG-014 Handshake timeout (butuh connection state machine)
└── BUG-015 Duplicate connection dedup by device_id

P2 (sisa)
├── BUG-024 Multi-subnet discovery
└── BUG-026 Hapus manual peer-{ip} placeholder

Architecture
├── ARCH-001 EventBus
├── ARCH-002 Session identity
└── ARCH-003 Split UI
```

Untuk P0 yang tersisa (identity, encryption, protocol validation lanjutan,
binary transfer), pendekatan patch satu-satu akan menambah technical debt.
Lebih masuk akal menjadikan **Protocol V2 + Security Foundation** sebagai
satu milestone besar (lihat `Implementation_plan.md`), lalu bug-bug lama
terkait protocol/identity ditutup bersamaan.

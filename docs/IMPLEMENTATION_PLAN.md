# Implementation Plan — peerc

> Disesuaikan dari rencana implementasi sebelumnya (saat proyek masih
> bernama `peerc`). Perubahan di versi ini: nama proyek → **peerc**, dan
> Phase 3 (Device Identity) ditambahkan ringkasan keputusan final soal
> kenapa IP/MAC/hostname/hardware-serial ditolak sebagai basis identity
> (detail lengkap ada di `BUG_REPORT.md` BUG-003).
>
> Status implementasi saat ini: Phase 1 (stabilisasi bug kritis di kode yang
> sudah ada) sebagian besar sudah jalan — lihat tabel status di
> `BUG_REPORT.md`. Phase 3 ke atas (identity, encryption, dst.) belum
> dimulai.

Target akhirnya:

```
┌────────────── Device A ──────────────┐
│                                      │
│ Identity (Ed25519)                   │
│ Secure Private Key                   │
│ Trusted Devices                      │
│                                      │
│        ↓ authenticated handshake     │
│                                      │
│ Ephemeral X25519                     │
│        ↓                             │
│ HKDF → Session Keys                  │
│        ↓                             │
│ ChaCha20-Poly1305                    │
│        ↓                             │
│ ┌───────────────┐                    │
│ │ Chat          │                    │
│ │ File Transfer │                    │
│ │ Clipboard     │                    │
│ └───────────────┘                    │
└──────────────────────────────────────┘
                 ↕ LAN
┌──────────────────────────────────────┐
│ Device B                             │
│ Identity + Trust + Secure Transport  │
└──────────────────────────────────────┘
```

## 0. Prinsip desain

Sebelum coding, tetapkan prinsip ini:

1. LAN dianggap hostile
2. Tidak ada server pusat
3. Public key boleh diketahui
4. Private key tidak pernah dikirim
5. Device ID berasal dari public key, bukan UUID acak, bukan IP/MAC, bukan hardware serial
6. Semua koneksi harus authenticated
7. Semua data setelah handshake terenkripsi
8. File dikirim sebagai binary, bukan Base64
9. File transfer harus resumable
10. Device yang dicabut trust-nya langsung ditolak
11. Kompromi satu device tidak boleh membocorkan sesi lama
12. Jangan pakai blockchain
13. QR bukan mekanisme utama

---

## Phase 1 — Stabilkan kode sekarang

Jangan langsung memasukkan crypto.

Pertama rapikan fondasi.

**Status: sebagian besar bug kritis di kode yang ada (path traversal, size
DoS, protocol schema validation, connection limits/timeout, ACK race, dsb)
sudah diperbaiki via patch bertahap — lihat `BUG_REPORT.md` untuk daftar
lengkap. Poin 1.1–1.3 di bawah (pemisahan protocol/frame formal, protocol
version field, binary framing) belum dikerjakan.**

### 1.1 Pisahkan protocol dari application

Sekarang `protocol.py` menangani framing + JSON.

Buat:

```
core/
├── protocol/
│   ├── frame.py
│   ├── messages.py
│   └── errors.py
```

`frame.py`:

```
encode_frame()
read_frame()
write_frame()
```

`messages.py`:

```
HELLO
HELLO_ACK
CHAT
CHAT_ACK

FILE_OFFER
FILE_ACCEPT
FILE_REJECT
FILE_CHUNK
FILE_DONE
```

---

### 1.2 Tetapkan protocol version

Contoh:

```json
{
  "version": 2,
  "type": "chat",
  "request_id": "...",
  "payload": {}
}
```

Jangan bergantung pada:

```json
{
  "type": "chat"
}
```

Karena nanti V3/V4 akan jauh lebih mudah.

---

### 1.3 Jangan gunakan JSON untuk data besar

Sekarang:

```
file
 ↓
Base64
 ↓
JSON
 ↓
TCP
```

Ganti menjadi:

```
control JSON
      ↓
binary frame
      ↓
raw bytes
```

Misalnya:

```
FILE_OFFER
FILE_ACCEPT
FILE_DATA
FILE_DONE
```

`FILE_DATA`:

```
transfer_id
sequence
offset
length
data
```

---

## Phase 2 — Security model

Sebelum implementasi crypto, buat threat model.

Yang harus dilindungi


| Ancaman            | Target                     |
| ------------------ | -------------------------- |
| Packet sniffing    | encrypted                  |
| Fake device        | authentication             |
| MITM               | authenticated key exchange |
| Replay             | nonce/session              |
| Malicious file     | validation                 |
| Path traversal     | sanitized filename         |
| Disk DoS           | size quota                 |
| Private key theft  | revocation                 |
| Compromised device | trust removal              |


---

## Phase 3 — Device Identity

Ini bagian paling penting.

Install library crypto yang matang, misalnya:

```
cryptography
```

Jangan implement algoritma crypto sendiri.

Buat:

```
core/
└── identity/
    ├── device_identity.py
    ├── key_storage.py
    └── fingerprint.py
```

### 3.0 Kenapa Ed25519, bukan alternatif lain (keputusan final)

Sebelum masuk ke detail generate key, ringkasan alasan tiap alternatif
ditolak (diskusi lengkap ada di `BUG_REPORT.md` BUG-003):

- **IP address** — berubah-ubah (DHCP renewal, ganti jaringan).
- **MAC address** — di-randomize per-network oleh kebanyakan OS modern demi
privacy, jadi tidak reliable lagi sebagai identifier stabil.
- **Hostname** — bisa diganti user kapan saja, dan tidak unik (dua device
bisa punya hostname sama).
- **UUID acak** (status sekarang) — memang stabil, tapi **tidak bisa
dibuktikan kepemilikannya**. Siapa pun bisa mengklaim UUID milik device
lain karena tidak ada private key di baliknya.
- **Hardware serial / machine-id / IMEI** — secara konsep permanen, tapi
tidak portable cross-platform (API berbeda total di Linux/Windows/macOS/
Android), dan privacy-invasive karena membocorkan identifier fisik
permanen ke peer lain di LAN.
- **TPM / Secure Enclave** — paling kuat secara teori (private key tidak
bisa diekstrak sama sekali), tapi tidak semua device punya akses yang
konsisten. Ini jadi kandidat **tempat penyimpanan** private key di masa
depan (lihat `KeyStore` abstraction di 3.3), bukan pengganti pendekatan
Ed25519 itu sendiri.

Kesimpulan: device identity berbasis **keypair Ed25519 yang digenerate
sekali di device dan disimpan lokal**. Identity ini "tidak berubah" bukan
karena terikat hardware/jaringan, tapi karena device terus memakai key yang
sama — dan karena ada private key di baliknya, kepemilikannya **bisa
dibuktikan** ke peer lain lewat signature (yang tidak bisa dilakukan UUID
biasa).

### 3.1 Generate Ed25519

Saat pertama kali aplikasi dijalankan:

```
generate_private_key()
generate_public_key()
```

Private key disimpan di secure storage.

Public key boleh disimpan biasa.

---

### 3.2 Device ID

Jangan:

```
UUID
```

Gunakan:

```
device_id = SHA256(public_key)
```

Misalnya:

```
Device ID:
7f:91:32:...
```

Dengan demikian identitas:

```
Device ID
     ↓
Public Key
     ↓
Private Key
```

bersifat konsisten.

---

### 3.3 Identity file

Secara konseptual:

```json
{
  "version": 1,
  "device_id": "...",
  "public_key": "...",
  "created_at": "..."
}
```

Jangan simpan private key plaintext kalau secure storage tersedia.

Untuk desktop:

```
Linux     → Secret Service / keyring
Windows   → DPAPI/Credential Manager
macOS     → Keychain
Android   → Android Keystore
```

Karena project ini Python cross-platform, buat abstraction:

```python
class KeyStore:
    def save_private_key(...)
    def load_private_key(...)
    def delete_private_key(...)
```

---

## Phase 4 — Trust Store

Buat:

```
core/
└── trust/
    ├── store.py
    ├── device.py
    └── revocation.py
```

Database sederhana:

```
trusted_devices
----------------
device_id
public_key
name
first_seen
last_seen
status
```

Status:

```
PENDING
TRUSTED
REVOKED
```

---

### TOFU

Untuk LAN app, TOFU cukup bagus.

Pertama kali:

```
Unknown Device
      ↓
Fingerprint:
AB:91:73:...
      ↓
Trust?
```

User approve.

Kemudian:

```
same public key → OK
different public key → WARNING
```

---

## Phase 5 — Discovery V2

Discovery sekarang menggunakan UDP broadcast.

Pertahankan itu.

Tetapi jangan percaya discovery sebagai authentication.

Discovery hanya menjawab:

> "Ada device di network."

Bukan:

> "Device ini terpercaya."

Broadcast:

```json
{
  "version": 2,
  "device_id": "...",
  "public_key": "...",
  "name": "...",
  "tcp_port": 5656
}
```

Semua field harus divalidasi (lihat BUG-023 di `BUG_REPORT.md` — validasi
dasar untuk field-field non-identity sudah jalan; validasi `public_key`
menyusul begitu Phase 3 selesai).

---

### Multi-subnet

Karena ada kemungkinan dua gedung:

```
Building A
   │
Router
   │
Building B
```

UDP broadcast biasanya tidak melewati router.

Maka discovery architecture:

```
Discovery
├── UDP Broadcast
├── mDNS
└── Manual IP
```

Jangan membuat semuanya bergantung pada broadcast.

Manual:

```
/connect 192.168.20.15
```

tetap harus tersedia (sudah jalan, termasuk IPv6 — lihat BUG-025).

---

## Phase 6 — Secure Handshake

Ini inti keamanan.

Jangan:

```
TCP
 ↓
HELLO
 ↓
langsung chat
```

Buat:

```
TCP
 ↓
Protocol negotiation
 ↓
Identity authentication
 ↓
Ephemeral key exchange
 ↓
Session established
 ↓
Encrypted application data
```

---

### 6.1 Handshake key

Identity:

```
Ed25519
```

Session:

```
X25519
```

Misalnya:

```
A:
Ed25519 private/public
X25519 ephemeral key

B:
Ed25519 private/public
X25519 ephemeral key
```

---

### 6.2 Authentication

A mengirim:

```
device_id
public_key_A
ephemeral_key_A
nonce
signature
```

Signature mencakup seluruh transcript handshake.

B memverifikasi:

```
signature
   ↓
public_key_A
   ↓
trusted?
```

Kemudian B melakukan hal yang sama.

Jangan hanya sign public key.

Sign transcript agar MITM tidak bisa mengganti parameter handshake.

---

## Phase 7 — Session Key

Setelah X25519:

```
shared_secret
      ↓
HKDF
      ↓
session keys
```

Jangan menggunakan shared secret langsung sebagai encryption key.

Gunakan domain separation.

Contoh konsep:

```
HKDF(
    shared_secret,
    salt,
    info="peerc-v2"
)
```

Kemudian hasilnya dipisah:

```
A → B encryption key
B → A encryption key
```

---

## Phase 8 — Encryption

Gunakan AEAD:

```
ChaCha20-Poly1305
```

atau:

```
AES-256-GCM
```

Pilih ChaCha20-Poly1305 untuk implementasi portable.

Setiap encrypted frame:

```
sequence
nonce
ciphertext
authentication tag
```

Nonce tidak boleh digunakan ulang dengan key yang sama.

Lebih aman jika nonce/sequence dikelola oleh session layer secara ketat.

---

## Phase 9 — Secure Transport Layer

Buat:

```
core/
└── transport/
    ├── tcp.py
    ├── secure.py
    ├── session.py
    └── timeout.py
```

Application tidak perlu tahu tentang crypto.

Jadi:

```
session.send(message)
```

bukan:

```
encrypt()
socket.send()
```

Arsitektur:

```
Application
     ↓
SecureSession
     ↓
EncryptedTransport
     ↓
TCP
```

---

## Phase 10 — Connection management

Perbaiki masalah yang sekarang.

Jangan key connection berdasarkan:

```
ip:port
```

Gunakan:

```
device_id
```

Karena port source TCP bisa berubah.

Tambahkan:

```
connect timeout     ✅ sudah (CONNECT_TIMEOUT, lihat BUG-014)
handshake timeout    ⏳ belum — butuh Phase 6 + connection state machine
idle timeout         ⏳ belum
maximum connections  ✅ sudah (MAX_CONNECTIONS, lihat BUG-016)
maximum frame size   🟡 sebagian — sudah ada untuk chat (MAX_CHAT_TEXT_SIZE), belum untuk file
```

Contoh:

```
CONNECT_TIMEOUT = 5s
HANDSHAKE_TIMEOUT = 5s
IDLE_TIMEOUT = 60s
MAX_FRAME = 16 MB
```

Untuk file jangan gunakan frame 100 MB.

---

## Phase 11 — Chat V2

Chat menjadi:

```json
{
  "type": "chat",
  "message_id": "...",
  "timestamp": 123,
  "text": "Hello"
}
```

ACK:

```json
{
  "type": "chat_ack",
  "message_id": "..."
}
```

Tambahkan:

```
message_id      ✅ sudah ada
timestamp
sender_device_id
```

---

### ACK race

Sekarang pending message dibuat setelah send.

**Status: sudah diperbaiki** — `register pending` sekarang terjadi
*sebelum* `send`, bukan sesudahnya (lihat BUG-022 di `BUG_REPORT.md`):

```
register pending
       ↓
send
       ↓
receive ACK
       ↓
resolve pending
```

---

## Phase 12 — File Transfer V2

Ini bagian yang paling perlu direwrite.

Arsitektur:

```
transfer/
├── manager.py
├── sender.py
├── receiver.py
├── chunker.py
├── resume.py
└── hashing.py
```

---

### File Offer

```json
{
  "type": "file_offer",
  "transfer_id": "...",
  "filename": "photo.jpg",
  "size": 12345678,
  "sha256": "...",
  "chunk_size": 262144
}
```

Receiver:

```
validate
 ↓
accept/reject
```

---

## Phase 13 — Path traversal fix

**Status: sudah diperbaiki** (lihat BUG-001 di `BUG_REPORT.md`).

Jangan pernah:

```python
os.path.join(downloads_dir, filename)
```

langsung.

Gunakan:

```
basename
sanitization
absolute-path check
symlink protection
destination confinement
```

Contoh:

```
../../important.txt
```

harus menjadi:

```
important.txt
```

atau ditolak.

Dan:

```
/etc/passwd
```

harus ditolak.

---

## Phase 14 — Size enforcement

**Status: sudah diperbaiki** (lihat BUG-002 di `BUG_REPORT.md`).

Kalau offer:

```
size = 10 MB
```

receiver hanya boleh menerima:

```
<= 10 MB
```

Bukan:

```
offer 10 MB
attacker send 10 GB
```

Track:

```
received_bytes
```

Setiap chunk:

```python
received_bytes += len(data)

if received_bytes > declared_size:
    abort()
```

---

## Phase 15 — Chunk validation

**Status: sudah diperbaiki** (lihat BUG-008 di `BUG_REPORT.md`) — strict
sequential transfer sudah jalan.

```python
expected_sequence = 0
```

Kemudian:

```
chunk 0
chunk 1
chunk 2
...
```

Jika:

```
chunk 7
```

datang saat expected:

```
6
```

ditolak (bukan diterima diam-diam). Out-of-order transfer dengan bitmap
masih backlog untuk kebutuhan resume (Phase 16).

---

## Phase 16 — Resume

Setelah transfer interruption:

```
file.part
```

disimpan.

Metadata:

```json
{
  "transfer_id": "...",
  "filename": "...",
  "size": 5000000000,
  "sha256": "...",
  "received": 2380000000
}
```

Reconnect:

```
resume?
```

Receiver:

```
offset = 2380000000
```

Sender melanjutkan dari sana.

---

## Phase 17 — Integrity

SHA-256 tetap digunakan.

Namun:

```
SHA256 ≠ encryption
```

SHA-256 digunakan untuk memastikan:

```
file dikirim utuh
```

Setelah selesai:

```
calculated_hash
        ==
declared_hash
```

Kalau berbeda:

```
TRANSFER_CORRUPTED
```

**Status: sudah diperbaiki** — checksum dari `file_offer` sekarang jadi
authoritative, `file_done` tidak lagi bisa menggantikannya (lihat BUG-010).

---

## Phase 18 — File encryption

Tidak perlu mengenkripsi file secara terpisah.

Karena:

```
File
 ↓
SecureSession
 ↓
AEAD
 ↓
TCP
```

sudah encrypted.

Ini lebih sederhana dan menghindari double encryption.

---

## Phase 19 — Transfer flow final

```
Sender                         Receiver

FILE_OFFER ───────────────────>
              validate
              sanitize
              check disk
              check size

<──────────── FILE_ACCEPT

FILE_DATA #0 ─────────────────>
FILE_DATA #1 ─────────────────>
FILE_DATA #2 ─────────────────>
...

FILE_DONE ────────────────────>

              SHA256
              verify
              rename .part

<──────────── FILE_COMPLETE_ACK
```

**Status:** `FILE_COMPLETE_ACK` sudah diimplementasikan (lihat BUG-012) —
sender sekarang menunggu ack ini sebelum menandai transfer selesai, bukan
langsung declare "done" setelah kirim byte terakhir.

---

## Phase 20 — Disk safety

Sebelum menerima file:

```
available disk space
```

harus dicek.

Misalnya:

```
file = 10 GB
free disk = 3 GB
```

langsung reject.

Tambahkan:

```
MAX_FILE_SIZE            ✅ sudah (MAX_INCOMING_FILE_SIZE)
MAX_CONCURRENT_TRANSFERS ⏳ belum
MAX_TOTAL_INCOMING_SIZE  ⏳ belum
```

---

## Phase 21 — Rate limiting

Karena LAN bisa hostile:

```
connection rate
handshake rate
file offer rate
chat message rate
```

dibatasi.

Misalnya konsep:

```
max 10 connection attempts / minute
max 5 simultaneous transfers
```

Angka final bisa dikonfigurasi. (Connection *count* limit sudah ada via
`MAX_CONNECTIONS` — lihat BUG-016 — tapi itu batas total, bukan rate.)

---

## Phase 22 — Discovery security

Discovery packet tidak dianggap terpercaya.

Misalnya attacker mengirim:

```json
{
  "device_id": "victim",
  "name": "Laptop Baim",
  "ip": "192.168.1.10"
}
```

Tidak masalah.

Ketika connect:

```
device_id
      ↓
public key
      ↓
signature
      ↓
trust store
```

baru dipercaya.

---

## Phase 23 — Device revocation

UI:

```
Trusted Devices

● Laptop
  ID: A8F2...
  Last seen: 2 min ago

● Phone
  ID: 91C3...
  Last seen: 5 min ago

[Revoke]
```

Revoke:

```
status = REVOKED
```

Connection:

```python
if device.status == REVOKED:
    reject()
```

---

## Phase 24 — Key rotation

Jika private key dicurigai bocor:

```
Revoke old identity
       ↓
Generate new keypair
       ↓
New device identity
       ↓
Trust again
```

Jangan mencoba "mengubah" private key lama.

---

## Phase 25 — Forward secrecy

Ini sangat penting untuk desain yang diinginkan.

Identity key:

```
long-term
```

Session key:

```
ephemeral
```

Jadi:

```
Ed25519 identity
       +
ephemeral X25519
       ↓
session key
```

Jika suatu hari private identity key dicuri, attacker tidak otomatis bisa
mendekripsi rekaman sesi lama, selama ephemeral keys/session secrets tidak
ikut bocor.

---

## Phase 26 — UI architecture (Event architecture) [SELESAI - v1.14.0]

Jangan lagi:

```
ChatSession
 ↓ modifies manager.on_message
FileTransferSession
 ↓ modifies manager.on_message
UI
 ↓ modifies manager.on_message
```

Ini akan semakin sulit dirawat (lihat ARCH-001 di `BUG_REPORT.md`).

Gunakan event bus:

```
Network
   ↓
EventBus
 ├── Security
 ├── Chat
 ├── Transfer
 ├── Discovery
 └── UI
```

Event:

```
ChatReceived
FileOffered
FileProgress
TransferCompleted
PeerConnected
PeerDisconnected
TrustRequired
SecurityWarning
```

**Status**: Selesai di v1.14.0 (`core/events.py`, `EventBus`, typed event classes,
`bridge_security_events`, penghapusan `manager.on_message` chaining di `chat.py`,
`file_transfer.py`, dan `ui.py`, serta pengujian di `tests/test_event_bus.py`).

---

## Phase 27 — Storage

Tambahkan SQLite.

Misalnya:

```
storage/
├── database.py
├── migrations.py
└── models.py
```

Tables:

```
devices
messages
transfers
settings
```

Jangan menyimpan private key di SQLite.

---

## Phase 28 — Logging

Gunakan:

```
logging
```

Bukan `print()`.

Level:

```
DEBUG
INFO
WARNING
ERROR
```

Security-sensitive data jangan dilog:

```
private key
session key
plaintext secrets
```

---

## Phase 29 — Testing

Buat:

```
tests/
├── unit/
│   ├── test_protocol.py
│   ├── test_identity.py
│   ├── test_crypto.py
│   ├── test_trust.py
│   └── test_transfer.py
│
├── integration/
│   ├── test_handshake.py
│   ├── test_chat.py
│   └── test_file_transfer.py
│
└── security/
    ├── test_path_traversal.py
    ├── test_replay.py
    ├── test_invalid_signature.py
    ├── test_oversized_transfer.py
    └── test_revoked_device.py
```

**Status:** struktur formal di atas belum dibuat, tapi cakupan setara sudah
ada secara flat di root repo: `test_security_fixes.py` (path traversal,
oversized transfer, protocol schema) dan `test_upgrade_fixes.py` (connection
limits/timeout, discovery validation). Reorganisasi ke struktur `tests/`
di atas cocok dilakukan bersamaan dengan Phase 1.1 (pemisahan `protocol.py`
ke `core/protocol/`).

---

## Phase 30 — Security test cases

Wajib dites:

Fake identity

```
Attacker claims device_id A
→ reject
```

Invalid signature

```
modified handshake
→ reject
```

MITM

```
A ↔ attacker ↔ B
→ authentication failure
```

Replay

```
old handshake
→ reject
```

Revoked key

```
valid signature + revoked device
→ reject
```

Path traversal

```
../../file
/etc/passwd
C:\Windows\...

→ reject.
```

**Status: sudah ditest** — lihat `test_security_fixes.py::test_path_traversal`.

Oversized file

```
declared = 10 MB
actual = 20 MB

→ abort.
```

**Status: sudah ditest** — lihat `test_security_fixes.py::test_oversized_declared_then_overflow_chunk`.

Corruption

```
modified chunk

→ authentication/integrity failure.
```

---

## Phase 31 — Performance

Target:

```
No Base64
No giant JSON
Streaming I/O
```

Pipeline:

```
Disk
 ↓
64/256 KB buffer
 ↓
Encrypt
 ↓
TCP
```

Receiver:

```
TCP
 ↓
Decrypt
 ↓
Disk
```

Jangan:

```
entire file → RAM
```

---

## Phase 32 — Concurrency

Gunakan async untuk:

```
network
connections
transfer
discovery
```

File hashing/I/O yang berat jangan menghambat event loop.

Gunakan:

```
asyncio.to_thread()
```

atau executor jika diperlukan.

---

## Phase 33 — Protocol state machine

Ini akan membuat implementation jauh lebih aman.

Connection:

```
CONNECTED
   ↓
HANDSHAKING
   ↓
AUTHENTICATED
   ↓
ESTABLISHED
   ↓
CLOSING
   ↓
CLOSED
```

Tidak boleh:

```
CONNECTED → FILE_DATA
```

sebelum:

```
ESTABLISHED
```

Ini juga prasyarat untuk menyelesaikan sisa BUG-014 (handshake timeout) —
tanpa state machine ini, tidak ada tempat yang jelas untuk menaruh timer
"belum ESTABLISHED dalam N detik → drop".

---

## Phase 34 — Transfer state machine

```
OFFERED
   ↓
ACCEPTED
   ↓
TRANSFERRING
   ↓
VERIFYING
   ↓
COMPLETED
```

Failure:

```
REJECTED
CANCELLED
FAILED
EXPIRED
```

Resume:

```
PAUSED
 ↓
RESUMING
 ↓
TRANSFERRING
```

---

## Phase 35 — Error protocol

Jangan lagi silent failure.

Buat:

```json
{
  "type": "error",
  "code": "AUTH_FAILED",
  "message": "Authentication failed"
}
```

Codes:

```
AUTH_FAILED
DEVICE_REVOKED
PROTOCOL_MISMATCH
INVALID_FRAME
TRANSFER_NOT_FOUND
SIZE_EXCEEDED
DISK_FULL
CHECKSUM_MISMATCH
TRANSFER_EXPIRED
```

`protocol.py` sudah punya `make_error()` sebagai starting point.

---

## Phase 36 — CLI/UI

Target command:

```
/pairs
/devices
/trust <id>
/revoke <id>
/connect <ip>
/send <file>
/cancel <transfer>
/resume <transfer>
/nick <name>
```

Contoh:

```
Devices

✓ Baim Laptop
  192.168.1.20
  Trusted

? Android
  192.168.1.31
  Pending

✗ Old Laptop
  Revoked
```

---

## Phase 37 — Security UX

Ketika device baru:

```
New device detected

Name: Android
Device ID: 91C3...
Fingerprint:
A2:73:19:...

[Trust] [Reject]
```

Kalau key berubah:

```
⚠ SECURITY WARNING

Device "Android" changed identity.

Previous fingerprint:
A2:73:19:...

New fingerprint:
71:9F:22:...

Possible reasons:
• device reinstalled
• key rotated
• identity compromised

[Trust New Key]
[Reject]
```

Ini jauh lebih penting daripada sekadar membuat crypto kuat.

---

## Phase 38 — Project structure final

Target akhirnya:

```
peerc/
│
├── app/
│   ├── main.py
│   └── config.py
│
├── core/
│   ├── protocol/
│   │   ├── frame.py
│   │   ├── messages.py
│   │   └── errors.py
│   │
│   ├── transport/
│   │   ├── tcp.py
│   │   ├── secure.py
│   │   └── session.py
│   │
│   ├── crypto/
│   │   ├── identity.py
│   │   ├── handshake.py
│   │   ├── key_exchange.py
│   │   └── encryption.py
│   │
│   └── identity/
│       ├── device.py
│       └── keystore.py
│
├── discovery/
│   ├── broadcast.py
│   ├── mdns.py
│   └── registry.py
│
├── trust/
│   ├── store.py
│   └── revocation.py
│
├── messaging/
│   ├── chat.py
│   └── ack.py
│
├── transfer/
│   ├── manager.py
│   ├── sender.py
│   ├── receiver.py
│   ├── chunk.py
│   ├── resume.py
│   └── hashing.py
│
├── storage/
│   ├── database.py
│   └── migrations.py
│
├── ui/
│   └── textual_app.py
│
└── tests/
    ├── unit/
    ├── integration/
    └── security/
```

---

## Phase 39 — Secure Storage (at-rest encryption)

**Depends on Phase 27** (Storage) — this phase encrypts data that Phase 27
defines the schema for (`messages`, `transfers`); it can't start for real
until that schema exists, or absorbs Phase 27's scope directly (see open
decision below).

Full design, threat model, and rationale: `**SECURE_STORAGE_DESIGN.md`**.
Summary only, here:

```
DEK (AES-256, random, generated once)
   │
   ├── wrapped by KEK(passphrase)   — Scrypt(passphrase, salt)
   └── wrapped by KEK(recovery code) — Scrypt(recovery code, salt)
```

- Passphrase doubles as the "login" — same passphrase unlocks the app AND
derives the key (via a KEK, never directly — see design doc for why).
**The wrapped-DEK blob may live in OS keyring storage, but that's just
where the bytes sit — unlocking always requires the passphrase.** No
auto-unlock from keyring/OS-login alone (considered and explicitly
rejected — doesn't cover "someone else picks up an already-unlocked
device").
- **Text chat vs. file actions have different friction, deliberately.**
Text chat is session-based (WhatsApp-like — unlock once, read/send
freely until idle timeout). File actions (Open/Export/Move to Secure
Storage/Delete) default to re-prompting for the passphrase **every
time**, independent of the chat session. The one exception: **Incoming
Transfer** (receiving a file from a peer) only needs yes/no — nothing
is decrypted/exposed at that point. All of this is user-configurable
via "don't ask again this session" and an optional separate "critical
action" key for Export specifically. Text and file messages get
**separate UI areas**, not interleaved into one timeline (unlike
WhatsApp) — the differing auth requirement is a property of *where*
something is, not something to track per-item.
- Recovery code generated once at first identity setup, shown once,
never stored — only used once to derive a second wrapped copy of the
DEK, so losing the passphrase doesn't mean losing the data.
- Two storage modes: **secure** (encrypted; chat history is always this)
and **normal** (plaintext; today's file-transfer behavior), chosen
per-transfer on the incoming-file dialog (default: secure). Five
distinct actions: **Incoming Transfer** (accept/reject, no key needed),
**Open** (ephemeral, stays secure, **must never execute the file** —
view/preview only), **Export** (permanent plaintext copy, explicit
warned confirmation), **Move to Secure Storage** (import an existing
local file, key required), **Delete**. Secure files are named by
opaque id, not original filename.
- Viewer-cache leak (decrypted content surviving in an external viewer's
own cache/temp files) is a known gap — mitigated by rendering in-app
wherever possible rather than handing files to an OS-level viewer.

**Status:** design fully resolved, including implementation-level specs
(see `SECURE_STORAGE_DESIGN.md` §11–§17: KDF, DB encryption approach,
Phase 27 absorption, default auto-lock, executable detection,
critical-action key mechanics, unified database schema, vault keyfile
format, passphrase/recovery-code requirements, nonce management, and the
in-memory/tmpfs database lifecycle). No code yet — this is the reference
doc for implementation.

---

## Phase 40 — Device Key Rotation

**Depends on Phase 3/4** (identity + trust store). Full design:
`SECURITY_MODEL.md` §13–16.

```
core/identity/
└── rotation.py   # generate transition cert, verify transition cert
```

- `TrustedDevice` (Phase 4) gains an identity-chain concept: a
`device_id` can be linked to a prior `device_id` via a **Transition
Certificate** — the old private key signs a statement authorizing the
new public key as its successor.
- On receiving a transition certificate for an already-`TRUSTED`
`device_id`, `TrustStore` verifies the signature against the *old*
(already-trusted) public key, and if valid, inserts the new
`device_id` as `TRUSTED` directly — no fresh TOFU `PENDING` step.
- A **compromise-triggered** rotation gets none of this: there's no
transition cert from a key that can't be trusted anymore, so the new
identity goes through ordinary TOFU like any unknown device.
- Un-provable rotation (claims to be a successor, signature doesn't
check out) is a `WARNING`-severity security event at minimum
(`SECURITY_MODEL.md` §29, Phase 41).

**Status:** design complete, no code yet.

## Phase 41 — Security Event Logging

**Extends Phase 28** (Logging) with the severity classification and
event types from `SECURITY_MODEL.md` §29.

```
core/security/
└── events.py   # SecurityEvent dataclass, severity enum, emit()
```

- Severity: `INFO` / `WARNING` / `HIGH` / `CRITICAL` (`SECURITY_MODEL.md`
§29's exact classification).
- Every module that already makes a security-relevant decision gets a
call site here, not a parallel logging system: `TrustStore.check()`
returning `KEY_CHANGED` or `REVOKED` (Phase 4), a handshake rejecting a
peer (Phase 6), an admin action (Phase 42) — each emits one
`SecurityEvent` at the point the decision is already made.
- Optionally signable for audit purposes when part of a group
(`GROUP_AUTHORITY_DESIGN.md` §13) — signing is Phase 42's concern, this
phase only defines the event shape and severity.

**Status:** selesai (`core/security/events.py`, integration call sites, and `tests/test_security_events.py`).

## Phase 42 — Group Authority System

Full design: `GROUP_AUTHORITY_DESIGN.md`.

```
core/group/
├── membership.py    # membership certificate issue/verify
├── policy.py        # policy schema + enforcement (core-level, not UI)
├── admin.py         # admin identity, multi-admin threshold signatures
└── audit.py         # signed audit log (uses Phase 41's event shape)
```

- Admin identity reuses `core/identity/` (Phase 3) exactly — an admin is
just a device whose public key is additionally recorded as a group
admin, not a separate key type.
- Membership certificate: signed `{device_id, public_key, group_id, role, permissions, issued_at, expires_at}` (`GROUP_AUTHORITY_DESIGN.md`
§4).
- Policy enforcement happens in `core/`, never only in `ui.py` — matches
the project's existing pattern (`core/protocol/messages.py`'s
`validate_message()`, `KeyStore`'s refusals) applied to group policy
checks specifically.
- Multi-admin threshold (`k`-of-`n` signature verification) for
high-stakes actions, per `GROUP_AUTHORITY_DESIGN.md` §14.

**Status:** design complete, no code yet.

## Phase 43 — Group-Gated Export Authorization

**Depends on Phase 39 (Secure Storage) and Phase 42 (Group Authority)**.
Full design: `GROUP_AUTHORITY_DESIGN.md` §Export Authorization.

- Resolves the integration question between the personal critical-action
key (`SECURE_STORAGE_DESIGN.md` §11.7) and group-managed Export
Authorization: **both are required (AND), not either/or**, when a
device is in a group with `allow_export` policy active.
  - Group's signed, short-lived Export Authorization capability answers
  "is this allowed at all, per policy" (an authorization check).
  - The personal passphrase/critical-action key answers "prove
  possession, unwrap the DEK" (a cryptographic check).
  - Neither substitutes for the other. A personal (non-group) device is
  unaffected — only the second gate ever applied to it, unchanged from
  Phase 39's original design.
- Export capability format, expiry, and nonce: `GROUP_AUTHORITY_DESIGN.md`
§12.

**Status:** design complete, no code yet.

## Phase 44 — Internet P2P Connectivity

Full design: `INTERNET_CONNECTIVITY_DESIGN.md`.

```
core/connectivity/
├── locator.py       # IP/port endpoint tracking, separate from identity
└── endpoint_update.py  # signed endpoint announcement + verification
```

- Identity (`device_id`, Phase 3) stays completely separate from Locator
(IP/port) — a device can change IP without changing identity.
- **Endpoint Update**: a signed announcement (reuses Phase 6's signing/
nonce-cache machinery) lets a peer safely update a known device's
locator without re-running TOFU.
- Shares its underlying pattern with Phase 40's Transition Certificate —
both are "prove continuity via a signature the receiving peer can
verify," just for two different kinds of change (locator vs. identity
key). See `INTERNET_CONNECTIVITY_DESIGN.md`'s dedicated section on why
this matters more over the Internet than on a LAN.

**Status:** design complete, no code yet.

## Phase 45 — Rendezvous Service

**Optional.** Full design: `INTERNET_CONNECTIVITY_DESIGN.md` §Rendezvous.

- Not a data server — only helps peers find each other's current
locator. Chat/file traffic never routes through it.
- Can be self-hosted, separate from Group Authority (Phase 42) — one
server doesn't have to do both jobs.

**Status:** design complete, no code yet.

## Phase 46 — NAT Traversal & Relay Fallback

**Optional, depends on Phase 44.** Full design:
`INTERNET_CONNECTIVITY_DESIGN.md` §Optional Relay.

- Direct P2P attempted first; relay only as fallback when NAT/firewall
prevents a direct path.
- Relay only ever sees already-encrypted (Phase 8) ciphertext — never
session plaintext.

**Status:** design complete, no code yet.

---

## Urutan implementasi yang disarankan

Jangan mengikuti urutan struktur folder di atas secara mentah. Kerjakan
seperti ini:

```
1. Fix critical bugs                    ✅ selesai (lihat CHANGELOG v1.1.1's baseline)
        ↓
2. Protocol V2                          ✅ selesai (v1.1.1–v1.3.0)
        ↓
3. Binary file transfer                 ✅ selesai (v1.3.0)
        ↓
4. Device identity                      ✅ selesai (v1.3.1–v1.4.0)
        ↓
5. Trust store                          ✅ selesai (v1.4.1–v1.5.0)
        ↓
6. Authenticated handshake              ✅ selesai (v1.6.0)
        ↓
7. Encrypted session (X25519+HKDF)      ✅ selesai (v1.7.0)
        ↓
8. Encryption (ChaCha20-Poly1305)       ✅ selesai (v1.8.0)
        ↓
9. Secure connection manager            ✅ selesai (v1.9.0 — Secure Transport Layer)
        ↓
10. File transfer security + resume     ✅ selesai (v1.10.0 — File Transfer V2, Phase 12-20)
        ↓
11. Device Key Rotation                 ✅ selesai (Phase 40)
        ↓
12. Security Event Logging              ✅ selesai (Phase 41)
        ↓
13. Discovery V2                        ⏳ belum ← kita di sini (Phase 5)
        ↓
14. Event architecture                  ⏳ belum (Phase 26)
        ↓
15. Secure Storage                      🟡 desain lengkap, belum ada kode
                                            (Phase 39 — SECURE_STORAGE_DESIGN.md)
        ↓
16. Group Authority System              🟡 desain lengkap, belum ada kode
                                            (Phase 42 — GROUP_AUTHORITY_DESIGN.md)
        ↓
17. Group-Gated Export Authorization    🟡 desain lengkap, belum ada kode
                                            (Phase 43, depends on Phase 39+42)
        ↓
18. Internet P2P Connectivity           🟡 desain lengkap, belum ada kode
                                            (Phase 44 — INTERNET_CONNECTIVITY_DESIGN.md)
        ↓
19. Rendezvous Service (optional)       🟡 desain lengkap, belum ada kode (Phase 45)
        ↓
20. NAT Traversal & Relay (optional)    🟡 desain lengkap, belum ada kode (Phase 46)
        ↓
21. UI security/trust UX                ⏳ belum (Phase 36/37)
        ↓
22. Automated tests                     🟡 sebagian — CI sudah jalan otomatis
                                            tiap push, lihat .github/workflows/tests.yml
        ↓
23. Performance testing                 ⏳ belum
        ↓
24. Security audit                      ⏳ belum
        ↓
25. Release
```

Status detail & versi persis per langkah: lihat `ROADMAP.md`.

## Prioritas versi

**Catatan:** milestone di bawah ini adalah label aspirational dari
rencana awal proyek — bukan nomor `pyproject.toml`/`CHANGELOG.md` yang
sebenarnya (yang sudah eksplisit ikut SemVer sejak `1.1.1`, dan sudah
lewat `v1.0` secara numerik di `1.5.0`, karena tiap fase selesai = bump
MINOR). Anggap ini sebagai nama kelompok kerja, bukan urutan rilis.
Status akurat + pemetaan ke versi asli ada di `ROADMAP.md`.

Milestone:

**v0.3 — Secure Foundation**

- Protocol V2 ✅ (v1.1.1–v1.3.0)
- binary frames ✅ (v1.3.0)
- device identity ✅ (v1.3.1–v1.4.0)
- Ed25519 ✅ (v1.3.1)
- trust store ✅ (v1.4.1–v1.5.0)
- authenticated handshake ⏳ belum (Phase 6)

**v0.4 — Encrypted Transport**

- X25519
- HKDF
- ChaCha20-Poly1305
- session keys
- replay protection
- timeouts

**v0.5 — Reliable Transfer**

- binary streaming ✅ (v1.3.0)
- size enforcement ✅
- safe filenames ✅
- SHA-256 ✅
- progress ✅
- cancel
- resume

**v0.6 — Discovery**

- UDP broadcast ✅
- mDNS
- manual connection ✅ (termasuk IPv6)
- multi-subnet support

**v0.7 — Persistence**

- SQLite ✅ (trust store, v1.4.1) — sisanya (message/transfer history)
digabung ke Phase 39, lihat SECURE_STORAGE_DESIGN.md §12
- message history ⏳ (Phase 39, diserap dari sini)
- transfer history ⏳ (Phase 39, diserap dari sini)
- trusted devices ✅ (v1.4.1–v1.5.0)

**v0.8 — Production Hardening**

- rate limiting
- connection limits ✅
- fuzz testing
- security tests 🟡 (sebagian, lihat Phase 29/30)
- resource limits
- better error handling ✅ (schema validation, lihat BUG-017/018)

**v1.0**

- Secure
- Reliable
- Fast
- Cross-platform
- Easy to use

---

## Dan satu hal yang penting

Jangan mulai dengan membuat `crypto.py` besar yang berisi semua kriptografi.

Buat crypto sebagai primitive yang kecil:

```
identity.py
    ↓
Ed25519

key_exchange.py
    ↓
X25519

kdf.py
    ↓
HKDF

encryption.py
    ↓
ChaCha20-Poly1305
```

Kemudian `handshake.py` yang menggabungkan semuanya.

Dengan begitu bisa diaudit:

```
Identity
   ↓
Authentication
   ↓
Key exchange
   ↓
Session
   ↓
Encryption
```

secara terpisah.

Langkah berikutnya yang disarankan untuk repo `peerc`: mulai dari
**Phase 1 → Protocol V2** terlebih dahulu, lalu baru crypto (Phase 3+). Itu
jauh lebih aman daripada menambahkan enkripsi ke arsitektur sekarang,
karena masalah framing, file transfer, connection lifecycle, dan trust
boundary-nya harus dibereskan dulu.
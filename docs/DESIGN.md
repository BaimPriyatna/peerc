# UI/UX Implementation Plan — peerc

> Disesuaikan dari dokumen desain sebelumnya. Perubahan di versi ini: nama
> proyek diganti ke **peerc**, dan bagian Device ID / Fingerprint (§6–§8)
> diperjelas bahwa nilai yang ditampilkan berasal dari **SHA-256 atas
> Ed25519 public key** — bukan UUID, bukan IP/MAC, bukan hardware serial
> (lihat `BUG_REPORT.md` BUG-003 untuk alasan penolakan alternatif lain).

## 1. Konsep UI utama

Targetnya bukan TUI yang penuh widget seperti desktop app, tetapi
terminal-native file sharing app yang cepat dipahami.

Inspirasi UX:

```
┌──────────────────────────────────────────────────────────────┐
│ peerc                                        ● LAN Connected │
├───────────────┬──────────────────────────────────────────────┤
│ DEVICES       │ CHAT                                         │
│               │                                              │
│ ● Laptop      │ You                                          │
│   Trusted     │ Hello!                                       │
│               │                                              │
│ ● Android     │ Android                                      │
│   Trusted     │ Here's the file.                             │
│               │                                              │
│ ? PC-Room     │                                              │
│   New Device  │                                              │
├───────────────┴──────────────────────────────────────────────┤
│ [Message...................................................] │
├──────────────────────────────────────────────────────────────┤
│ 3 devices • Secure • 1 transfer                              │
└──────────────────────────────────────────────────────────────┘
```

Fokus:

- device-centric
- security status selalu terlihat
- transfer progress jelas
- keyboard-first
- mouse optional
- tidak terlalu banyak border/dekorasi

---

## 2. Struktur navigasi

Jangan membuat semuanya menjadi satu screen.

Gunakan beberapa view:

```
Main
├── Chat
├── Devices
├── Transfers
├── History
└── Settings
```

Navigation:

```
Tab / 1-5
```

Contoh:

```
1 Chat
2 Devices
3 Transfers
4 History
5 Settings
```

Dan:

```
q → quit
? → help
Esc → back
```

---

## 3. Main Screen

Chat menjadi default screen.

Layout:

```
┌───────────────────────────────────────────────┐
│ peerc                            ● Secure LAN │
├──────────────┬────────────────────────────────┤
│ DEVICES      │ CHAT                           │
│              │                                │
│ ● Laptop     │ Baim                           │
│ ● Android    │ Hello                          │
│ ? Desktop    │                                │
│              │ Android                        │
│              │  📎 photo.jpg                  │
│              │                                │
├──────────────┴────────────────────────────────┤
│ > Type a message...                           │
├───────────────────────────────────────────────┤
│ Enter Send   Ctrl+F File   Tab Switch   ? Help│
└───────────────────────────────────────────────┘
```

---

## 4. Device sidebar

Ini salah satu bagian paling penting.

Device ditampilkan berdasarkan status.

```
DEVICES

● Laptop
  Trusted
  192.168.1.10

● Android
  Trusted
  192.168.1.20

? PC-ROOM
  New device

✕ Old Laptop
  Revoked
```

Status jangan hanya mengandalkan warna.

Gunakan icon:

```
●  online
○  offline
?  pending
✓  trusted
!  warning
✕  revoked
```

Jadi terminal tanpa warna pun tetap readable.

---

## 5. Security indicator

Header:

```
● Secure
```

bisa berubah menjadi:

```
● Secure
! Verification required
✕ Connection insecure
```

Tetapi jangan menampilkan jargon crypto kepada user biasa.

Misalnya ketika device trusted:

```
✓ Trusted device
```

Detail fingerprint hanya ketika user membuka detail.

---

## 6. Device Detail

Tekan:

```
Enter
```

pada device.

Muncul:

```
┌─────────────────────────────────────┐
│ Device                              │
├─────────────────────────────────────┤
│ Name        Android                 │
│ Status      ● Online                │
│ Trust       ✓ Trusted               │
│ Address     192.168.1.20:5656       │
│                                     │
│ Device ID                           │
│ 91C3 7A42 8F21 ...                  │
│                                     │
│ Fingerprint                         │
│ A82F 19C3 77B1 ...                  │
│                                     │
│ Last seen   2 minutes ago           │
│                                     │
│ [Send File] [Chat] [Revoke]         │
└─────────────────────────────────────┘
```

**Catatan implementasi:** `Device ID` dan `Fingerprint` di atas **bukan**
dua nilai independen yang perlu digenerate terpisah — keduanya berasal dari
Ed25519 public key milik device tersebut:

```
Ed25519 public key
        ↓ SHA-256
   device_id (dipakai internal, mis. di peer registry)
        ↓ format hex berkelompok, mis. "A8 2F 19 C3 ..."
   fingerprint (yang ditampilkan ke user untuk verifikasi manual)
```

Karena berasal dari public key, nilai ini **tidak pernah berubah** selama
private key device tidak diganti — beda dengan IP/MAC yang bisa berubah
kapan saja, dan beda dengan UUID acak yang tidak bisa dibuktikan
kepemilikannya. Lihat `BUG_REPORT.md` BUG-003 untuk alasan lengkap kenapa
IP/MAC/hostname/hardware-serial ditolak sebagai basis identity.

---

## 7. New Device UX

Saat device baru ditemukan:

```
┌──────────────────────────────────────────┐
│ New device detected                      │
├──────────────────────────────────────────┤
│                                          │
│ Android                                  │
│                                          │
│ Fingerprint                              │
│ A82F 19C3 77B1 9D20                      │
│                                          │
│ This device is not trusted yet.          │
│                                          │
│ [T] Trust        [R] Reject              │
│                                          │
└──────────────────────────────────────────┘
```

Jangan otomatis trust device hanya karena ditemukan melalui discovery.

---

## 8. Key Change Warning

Ini harus menjadi UX khusus.

Jika public key device berubah — misalnya karena device di-reset dan
generate keypair baru (lihat Implementation_plan.md Phase 24, key
rotation):

```
┌──────────────────────────────────────────┐
│ ⚠ SECURITY WARNING                       │
├──────────────────────────────────────────┤
│ Android has changed its identity.        │
│                                          │
│ Previous                                 │
│ A82F 19C3 77B1                           │
│                                          │
│ Current                                  │
│ 71AC 44E1 9320                           │
│                                          │
│ This may mean:                           │
│ • the device was reinstalled             │
│ • its identity was rotated               │
│ • the device may be compromised          │
│                                          │
│ [Reject]       [Trust New Identity]      │
└──────────────────────────────────────────┘
```

Ini jauh lebih berguna daripada hanya:

```
AUTH_FAILED
```

---

## 9. Chat UX

Chat jangan seperti terminal biasa:

```
Alice: hello
Bob: hi
```

Buat lebih readable:

```
Baim
14:32
Hello!

Android
14:33
Hi, sending the file.
```

Tetapi jangan terlalu banyak whitespace agar terminal kecil tetap nyaman.

---

## 10. File attachment

Chat dapat menampilkan:

```
Android

┌───────────────────────────────┐
│ 📎 photo.jpg                  │
│ 12.4 MB                       │
│                               │
│ ✓ Received                    │
└───────────────────────────────┘
```

Untuk transfer aktif:

```
photo.jpg
██████████████░░░░░░  67%
8.3 / 12.4 MB
↓ 18.4 MB/s
ETA 00:04
```

---

## 11. Transfers View

Semua transfer aktif dikumpulkan di sini.

```
TRANSFERS

↓ photo.jpg
  Android
  ███████████░░░ 72%
  8.9 / 12.4 MB
  18.2 MB/s
  ETA 00:02

↑ archive.zip
  Laptop
  ██████░░░░░░░░ 41%
  410 / 1000 MB
  32.1 MB/s
  ETA 00:18
```

Keyboard:

```
p  Pause
r  Resume
c  Cancel
Enter  Details
```

---

## 12. Transfer Details

```
Transfer

File
ubuntu.iso

Size
4.2 GB

From
Laptop

Status
Transferring

Progress
63%

Speed
42.3 MB/s

ETA
00:31

Integrity
SHA-256 pending

Encryption
✓ Secure session

[Pause] [Cancel]
```

---

## 13. Transfer completion

Jangan hanya:

```
Done
```

Tampilkan:

```
✓ Transfer complete

ubuntu.iso
4.2 GB

From: Laptop
Time: 01:42
SHA-256: Verified

Saved to:
~/Downloads/ubuntu.iso
```

---

## 14. Error UX

Jangan expose traceback ke UI normal.

Buruk:

```
ConnectionResetError: [Errno 104] ...
```

Lebih baik:

```
✕ Transfer failed

ubuntu.iso

The connection was interrupted.

The transfer can be resumed when the device reconnects.

[Resume] [Close]
```

Detail teknis bisa:

```
d → Show technical details
```

---

## 15. Chat dengan multiple devices

Jangan memaksa satu global chat.

Sidebar:

```
DEVICES

● Android
  2 unread

● Laptop
  0 unread

● Desktop
  5 unread
```

Klik Android:

```
CHAT — ANDROID
```

Kemudian Laptop:

```
CHAT — LAPTOP
```

---

## 16. Multi-device transfer

Nantinya:

```
Ctrl+F
```

muncul:

```
Send File

Select device:

> Android
  Laptop
  Desktop
```

Kemudian file picker terminal.

Kalau belum mau membuat native file picker, MVP cukup:

```
/send ~/Pictures/photo.jpg
```

TUI tetap dapat memanggil command tersebut.

---

## 17. Command palette

Ini menurut saya penting.

Tekan:

```
Ctrl+P
```

atau:

```
:
```

Muncul:

```
┌──────────────────────────────────────────┐
│ > send                                   │
├──────────────────────────────────────────┤
│ Send file                                │
│ Send clipboard                           │
│ Open device                              │
│ Revoke device                            │
│ Settings                                 │
└──────────────────────────────────────────┘
```

Jadi user tidak perlu menghafal semua shortcut.

---

## 18. CLI tetap tersedia

TUI adalah interface utama:

```
peerc
```

Tetapi CLI:

```
peerc send ./photo.jpg --device <id>
peerc devices
peerc trust <id>
peerc revoke <id>
peerc history
```

Ini berguna untuk:

- scripting
- automation
- SSH
- headless machine
- debugging

---

## 19. Responsive terminal

Karena terminal bisa:

```
80x24
120x40
200x60
```

UI harus adaptive.

80 columns

```
┌──────────────────────────────┐
│ Chat                         │
│                              │
│ Messages                     │
│                              │
│                              │
│ > message                    │
└──────────────────────────────┘
```

Sidebar bisa disembunyikan.

120+

```
┌─────────────┬───────────────────────────┐
│ Devices     │ Chat                      │
└─────────────┴───────────────────────────┘
```

160+

```
┌────────────┬────────────────────┬───────┐
│ Devices    │ Chat               │ Info  │
│            │                    │       │
│            │                    │       │
└────────────┴────────────────────┴───────┘
```

---

## 20. Theme

Saya sarankan dark-first, karena terminal environment.

Tetapi jangan hardcode warna.

Buat theme:

```
theme/
├── dark.tcss
└── light.tcss
```

Gunakan semantic colors:

```
success
warning
error
muted
accent
primary
```

Bukan:

```
green
red
blue
```

di seluruh code.

---

## 21. Accessibility

Jangan mengandalkan warna.

Contoh buruk:

```
🟢 = trusted
🔴 = revoked
```

Lebih baik:

```
✓ Trusted
✕ Revoked
! Warning
```

Dan:

```
NO_COLOR=1
```

tetap harus readable.

---

## 22. Keyboard-first

Semua operasi penting harus bisa dilakukan tanpa mouse.

```
Tab       next widget
Shift+Tab previous
Enter     select
Esc       back
Ctrl+P    command palette
Ctrl+F    send file
Ctrl+L    focus chat
Ctrl+R    refresh
?         help
q         quit
```

---

## 23. Help screen

Tekan `?`.

```
KEYBOARD SHORTCUTS

Navigation
  Tab       Move focus
  Enter     Select
  Esc       Back

Chat
  Ctrl+L    Focus message
  Ctrl+F    Send file

Transfers
  p         Pause
  r         Resume
  c         Cancel

Devices
  t         Trust
  x         Revoke

General
  Ctrl+P    Command palette
  Ctrl+R    Refresh
  ?         Help
  q         Quit
```

---

## 24. Notification system

Jangan membuat popup untuk semuanya.

Gunakan notification/toast:

```
✓ File received

⚠ New device detected

✕ Transfer failed
```

Level:

```
INFO
SUCCESS
WARNING
ERROR
SECURITY
```

Security event harus lebih menonjol.

---

## 25. Status bar

Bagian bawah:

```
3 devices • 1 transfer • ✓ Secure
```

atau:

```
3 devices • 1 transfer • ! Verification required
```

Jadi user selalu tahu kondisi aplikasi.

---

## 26. Settings

Jangan terlalu banyak setting di awal.

```
SETTINGS

General
  Device name
  Download directory
  Start minimized

Network
  TCP port
  Discovery
  mDNS

Security
  Trusted devices
  Key management
  Require approval

Transfers
  Max concurrent transfers
  Auto resume
  Max incoming file size

Appearance
  Theme
  Compact mode
```

---

## 27. Arsitektur UI

Karena kamu menggunakan Python + Textual, akan dibuat:

```
ui/
├── app.py
├── screens/
│   ├── main.py
│   ├── devices.py
│   ├── transfers.py
│   ├── history.py
│   ├── settings.py
│   └── help.py
│
├── widgets/
│   ├── device_list.py
│   ├── device_card.py
│   ├── chat_view.py
│   ├── message_input.py
│   ├── transfer_item.py
│   ├── progress_bar.py
│   ├── security_badge.py
│   ├── notification.py
│   └── command_palette.py
│
├── dialogs/
│   ├── trust_device.py
│   ├── revoke_device.py
│   ├── transfer_details.py
│   └── security_warning.py
│
└── styles/
    ├── dark.tcss
    └── light.tcss
```

---

## 28. UI jangan mengakses network langsung

Ini penting.

Jangan:

```
UI
 ↓
socket
 ↓
TCP
```

Tetapi:

```
┌── ChatService
             │
UI → AppState ├── TransferService
             │
             ├── DeviceService
             │
             └── SecurityService
```

UI hanya mengamati state.

---

## 29. App State

Buat central state:

```
AppState
```

isinya:

```
devices
connections
active_chat
messages
transfers
notifications
security_events
```

Misalnya:

```
DeviceState
{
    id,
    name,
    address,
    status,
    trust_status,
    fingerprint
}
```

UI melakukan render berdasarkan state tersebut.

---

## 30. Event architecture

Network menghasilkan:

```
PeerDiscovered
PeerConnected
PeerDisconnected

TrustRequired
SecurityWarning

MessageReceived
MessageSent

TransferStarted
TransferProgress
TransferPaused
TransferCompleted
TransferFailed
```

Kemudian:

```
Event
 ↓
AppState
 ↓
UI refresh
```

Ini akan menghilangkan masalah handler chaining dari implementasi sekarang
(lihat `BUG_REPORT.md` ARCH-001).

---

## 31. UX flow final

Pertama kali menjalankan

```
peerc
      ↓
Generate device identity
      ↓
Main TUI
      ↓
Discover devices
```

User melihat:

```
? Android
  New device
```

Tekan Enter:

```
Fingerprint
A82F 19C3 ...

[T] Trust
```

Trust.

Kemudian:

```
✓ Android
  Trusted
```

---

Mengirim file

```
Ctrl+F
 ↓
Select device
 ↓
Select file
 ↓
FILE_OFFER
 ↓
Receiver accepts
 ↓
Progress
 ↓
SHA-256 verification
 ↓
✓ Complete
```

---

Device dicurigai

```
⚠ Identity changed
```

User:

```
Reject
```

Device menjadi:

```
✕ Revoked
```

---

## 32. Implementation order

Urutan pengerjaan UI:

```
1. App shell
      ↓
2. Main screen
      ↓
3. Device sidebar
      ↓
4. Chat view
      ↓
5. Transfer view
      ↓
6. Notifications
      ↓
7. Device detail
      ↓
8. Trust/revoke dialogs
      ↓
9. Security warning
      ↓
10. Command palette
      ↓
11. Settings
      ↓
12. History
      ↓
13. Responsive layout
      ↓
14. Theme
      ↓
15. Accessibility
      ↓
16. CLI integration
```

## Target akhirnya

```
PEERC

       ┌─────── Main ───────┐
       │                    │
       │  Devices           │
       │  ──────────────    │
       │  ✓ Android         │
       │  ✓ Laptop          │
       │  ? Desktop         │
       │                    │
       │  Chat              │
       │  ──────────────    │
       │  Hello             │
       │  📎 photo.jpg      │
       │                    │
       │  Transfers         │
       │  ███████░ 72%      │
       │                    │
       └────────────────────┘

       ✓ Secure • 3 Devices
```

Intinya: TUI ini sebaiknya terasa seperti aplikasi desktop yang kebetulan
berjalan di terminal, bukan seperti kumpulan command yang diberi warna.
Textual cocok untuk itu. Dan karena security menjadi fitur utama project,
Trust/Identity/Security Warning harus menjadi bagian first-class dari UI,
bukan sesuatu yang tersembunyi di log.

---

## 33. Scrollable panels (btop-style)

> Inspirasi: btop menampilkan scrollbar yang terlihat jelas di setiap
> panel (process list, menu, dsb), bisa di-drag dengan mouse, dan scroll
> wheel langsung bekerja di panel mana pun yang sedang di-hover.

Kondisi saat ini: `RichLog` dan `ListView` sudah punya scroll internal
dari Textual, tetapi scrollbar default-nya sangat tipis dan hampir tidak
terlihat — user sering tidak sadar bahwa konten bisa di-scroll.

Target:

```
┌─ DEVICES ───────────┐  ┌─ CHAT ─────────────────────────────────┐
│ ● Laptop             │▲│ Baim                            14:32  │▲
│   Trusted            │█│ Hello!                                 │ │
│ ● Android            │█│                                        │ │
│   Trusted            │ │ Android                         14:33  │█│
│ ? Desktop            │ │ Hi, ini filenya.                       │█│
│   New device         │ │                                        │█│
│                      │ │ 📎 photo.jpg                           │ │
│                      │▼│ ✓ Received (12.4 MB)                   │▼│
└──────────────────────┘ └─────────────────────────────────────────┘
```

Aturan scrollbar:

- Scrollbar harus **selalu terlihat** (`overflow-y: auto`) — jangan hidden.
- Scrollbar harus bisa **di-drag** dengan mouse (Textual native support).
- **Scroll wheel** harus bekerja di panel yang sedang di-hover, tanpa perlu
  klik dulu untuk focus.
- `scrollbar-gutter: stable` agar layout tidak loncat saat scrollbar
  muncul/hilang.
- Scrollbar warna harus kontras dengan background panel, menggunakan
  semantic color (`$accent` atau `$primary`), bukan hardcoded.

---

## 34. Clickable UI elements

> Inspirasi: btop memungkinkan klik di mana saja — column header untuk
> sort, process item untuk select, menu button untuk navigate. Semua
> interaksi keyboard juga bisa dilakukan dengan mouse.

Prinsip: **keyboard-first, mouse-friendly**. Semua operasi utama tetap
bisa dilakukan via keyboard, tetapi mouse harus menjadi cara yang sama
valid untuk berinteraksi.

Target click areas:

```
Area                         Klik Action
─────────────────────────    ──────────────────────────────
Peer item di sidebar         Switch active chat ✅ (sudah ada)
Chat header ("CHAT — X")     Buka device detail popup
File attachment di chat      Open file / show transfer detail
Transfer progress bar        Show transfer detail modal
Status bar item              Toggle detail popup
Tab headers (jika ada)       Switch view
Scrollbar                    Drag scroll ✅ (Textual native)
Notification toast           Dismiss / navigate to source
```

Implementasi click handler pada widget:

```python
class ClickablePanel(Vertical):
    """Container panel yang merespon klik."""

    class PanelClicked(Message):
        def __init__(self, panel_id: str) -> None:
            super().__init__()
            self.panel_id = panel_id

    def on_click(self, event: Click) -> None:
        self.post_message(self.PanelClicked(self.id or ""))
```

Setiap panel yang clickable harus memiliki:

- **Hover effect** — border atau background berubah saat mouse hover.
- **Cursor change** — pointer cursor saat hover di atas clickable element.
- **Visual feedback** — brief flash atau highlight saat diklik.

---

## 35. Section separation — panel boxes

> Inspirasi: btop menggunakan box border dengan title label di setiap
> panel (CPU, MEM, NET, PROC), sehingga setiap section langsung jelas
> fungsinya bahkan tanpa membaca kontennya.

Kondisi saat ini: semua section hanya menggunakan `border: solid $accent`
yang sama — tidak ada visual hierarchy, tidak ada label.

Target: setiap section menjadi "panel box" dengan title.

Area konten utama (di sebelah kanan sidebar) memiliki **dua tab**:
**Chat** dan **File**. Kedua tab menempati **posisi yang sama** — saat
user klik tab File, konten Chat digantikan oleh konten File, dan
sebaliknya. Ini **per-peer**, artinya setiap peer punya chat history
dan file list masing-masing.

```
┌─ DEVICES (3) ──────┐  ┌─ [Chat] [File] — Android ─────────────┐
│                    │  │                                       │
│  content...        │  │  (tab Chat atau File ditampilkan      │
│                    │  │   di area yang sama ini)              │
│                    │  │                                       │
└────────────────────┘  └───────────────────────────────────────┘
```

Aturan panel boxes:

- Gunakan `border: round` (bukan `solid`) untuk kesan modern.
- Setiap panel **wajib punya title** via `border_title` property.
- Title menampilkan **nama section + informasi kontekstual**:
  - `DEVICES (3)` — nama + jumlah device
  - `[Chat] [File] — Android` — tab buttons + active peer
  - `TRANSFERS (1 active)` — nama + jumlah transfer aktif
  - `INPUT` — untuk input box
- Tab yang sedang aktif di-highlight (`bold + underline`), tab tidak
  aktif di-dim.
- Panel yang sedang **active/focused** harus memiliki border warna
  berbeda (`$primary`) dari panel non-active (`$accent`).
- **Hover** pada panel mengubah border ke `$secondary`.

Implementasi border_title dan tab switching di Python:

```python
def _refresh_panel_titles(self) -> None:
    """Update semua panel title berdasarkan state terkini."""
    peer_count = len(self.registry.list_peers())
    peer_panel = self.query_one("#peer-panel")
    peer_panel.border_title = f"DEVICES ({peer_count})"

    active_name = "—"
    if self.active_peer_id:
        peer = self.registry.get(self.active_peer_id)
        if peer:
            active_name = peer.name
    content_panel = self.query_one("#content-panel")
    if self.active_tab == "chat":
        content_panel.border_title = f"[Chat] File — {active_name}"
    else:
        content_panel.border_title = f"Chat [File] — {active_name}"

def _switch_tab(self, tab: str) -> None:
    """Switch antara tab Chat dan File di area konten."""
    self.active_tab = tab
    chat_view = self.query_one("#chat-view")
    file_view = self.query_one("#file-view")
    chat_view.display = (tab == "chat")
    file_view.display = (tab == "file")
    self._refresh_panel_titles()
```

---

## 36. Layout baru dengan tab Chat / File

### Normal view (120+ columns) — Tab Chat aktif

```
┌─────────────────────────────────────────────────────────────────────┐
│ peerc — Baim (91c37a42)                            ● Secure │ 22:41 │
├──── DEVICES (3) ─────┬──── [Chat] File — Android ───────────────────┤
│                      │▲                                             │▲
│ ► ● Android          │ │ Baim                             14:32     │ │
│     192.168.1.20     │ │ Hello!                                     │ │
│                      │ │                                            │█│
│   ● Laptop           │█│ Android                          14:33     │█│
│     192.168.1.10     │█│ Hi, ini filenya.                           │█│
│                      │ │                                            │ │
│   ? Desktop          │ │ You                              14:34     │ │
│     New device       │ │ Ok, got it!                                │ │
│                      │▼│                                            │▼│
├──────────────────────┴──────────────────────────────────────────────┤
│ > Type a message...                                     Ctrl+F File │
├─────────────────────────────────────────────────────────────────────┤
│ 3 devices • ✓ Secure • 1 transfer active                            │
└─────────────────────────────────────────────────────────────────────┘
```

### Normal view — Tab File aktif (posisi sama, konten berganti)

```
┌─────────────────────────────────────────────────────────────────────┐
│ peerc — Baim (91c37a42)                            ● Secure │ 22:41 │
├──── DEVICES (3) ─────┬──── Chat [File] — Android ───────────────────┤
│                      │▲                                             │▲
│ ► ● Android          │ │ SHARED FILES                               │ │
│     192.168.1.20     │ │                                            │ │
│                      │ │ ↓ photo.jpg         12.4 MB  ✓ Received   │ │
│   ● Laptop           │█│ ↓ document.pdf       2.1 MB  ✓ Received   │█│
│     192.168.1.10     │█│ ↑ archive.zip        4.2 GB  ███░ 63%     │█│
│                      │ │ ↓ notes.txt          48 KB   ✓ Received   │ │
│   ? Desktop          │ │                                            │ │
│     New device       │ │                                            │ │
│                      │▼│                                            │▼│
├──────────────────────┴──────────────────────────────────────────────┤
│ /send <filepath>  or drag file here                 Ctrl+C Chat     │
├─────────────────────────────────────────────────────────────────────┤
│ 3 devices • ✓ Secure • 1 transfer active                            │
└─────────────────────────────────────────────────────────────────────┘
```

### Compact view (80 columns — sidebar auto-hidden)

```
┌──────────────────────────────────────────────────────────────────┐
│ peerc — Baim                                     ● Secure │ 22:41│
├──── [Chat] File — Android ───────────────────────────────────────┤
│                                                                  │▲
│ Baim                                                   14:32     │ │
│ Hello!                                                           │█│
│                                                                  │█│
│ Android                                                14:33     │ │
│ Hi, ini filenya.                                                 │ │
│                                                                  │▼│
├──────────────────────────────────────────────────────────────────┤
│ > Type a message...                                              │
├──────────────────────────────────────────────────────────────────┤
│ 3 devices • ✓ Secure                  Ctrl+D Devices  Ctrl+T Tab │
└──────────────────────────────────────────────────────────────────┘
```

### Wide view (160+ columns — three-column)

```
┌────────────┬──────────────────────────────────────┬──────────────┐
│ DEVICES(3) │ [Chat] File — Android                │ DEVICE INFO  │
│            │                                      │              │
│ ► Android  │ Baim            14:32                │ ● Android    │
│   Laptop   │ Hello!                               │ Trusted      │
│ ? Desktop  │                                      │ 192.168.1.20 │
│            │ Android         14:33                │              │
│            │ Hi, ini filenya.                     │ Fingerprint  │
│            │                                      │ A82F 19C3... │
│            │                                      │              │
│            │                                      │ [Send File]  │
│            │                                      │ [Revoke]     │
└────────────┴──────────────────────────────────────┴──────────────┘
```

Breakpoint responsive:

```
< 100 cols   → sidebar hidden, tab Chat/File only + status bar hint
100-159 cols → sidebar + tab Chat/File (two-column)
160+ cols    → sidebar + tab Chat/File + device info (three-column)
```

---

## 37. Implementasi CSS Textual

Berikut TCSS lengkap yang menggantikan CSS inline di `ChatApp`:

```css
/* ═══════ Global ═══════ */
Screen {
    background: $background;
}

/* ═══════ Panel Boxes ═══════ */
.panel-box {
    border: round $accent;
    border-title-color: $text;
    border-title-style: bold;
    border-title-align: left;
    padding: 0 1;
    margin: 0;
}

.panel-box:focus-within {
    border: round $primary;
    border-title-color: $primary;
}

.panel-box:hover {
    border: round $secondary;
}

/* ═══════ Sidebar ═══════ */
#peer-panel {
    width: 28;
    min-width: 20;
    max-width: 40;
    overflow-y: auto;
    scrollbar-size: 1 1;
    scrollbar-color: $accent;
    scrollbar-background: $surface;
    scrollbar-gutter: stable;
}

#peer-panel .peer-item {
    padding: 0 1;
    height: auto;
}

#peer-panel .peer-item:hover {
    background: $boost;
}

#peer-panel .peer-item.--active {
    background: $primary 20%;
    border-left: thick $primary;
}

/* ═══════ Content Area (Chat/File tabs) ═══════ */
#content-panel {
    overflow-y: auto;
    scrollbar-size: 1 1;
    scrollbar-color: $primary;
    scrollbar-background: $surface;
    scrollbar-gutter: stable;
}

/* Tab buttons in border_title area */
.tab-button {
    padding: 0 1;
    height: 1;
    min-width: 8;
    border: none;
    background: transparent;
    color: $text-muted;
}

.tab-button:hover {
    color: $text;
    text-style: bold;
}

.tab-button.--active {
    color: $primary;
    text-style: bold underline;
}

/* Chat view (shown when Chat tab active) */
#chat-view {
    display: block;
}

/* File view (shown when File tab active) */
#file-view {
    display: none;
}

#content-panel.tab-file #chat-view {
    display: none;
}

#content-panel.tab-file #file-view {
    display: block;
}

/* File list items */
.file-item {
    height: 2;
    padding: 0 1;
}

.file-item:hover {
    background: $boost;
}

.file-item .file-status-received {
    color: $success;
}

.file-item .file-status-sending {
    color: $warning;
}

/* ═══════ Input Box ═══════ */
#input-panel {
    height: 3;
    border: round $accent;
    border-title-color: $text-muted;
}

#input-panel:focus-within {
    border: round $primary;
}

/* ═══════ Transfer Panel ═══════ */
#transfer-panel {
    height: auto;
    max-height: 8;
    overflow-y: auto;
    scrollbar-size: 1 1;
    display: none;  /* hidden when no active transfers */
}

#transfer-panel.has-transfers {
    display: block;
}

.transfer-item {
    height: 2;
    padding: 0 1;
}

.transfer-item:hover {
    background: $boost;
}

/* ═══════ Status Bar ═══════ */
#status-bar {
    height: 1;
    dock: bottom;
    background: $surface;
    color: $text-muted;
    padding: 0 1;
}

/* ═══════ Scrollbar Styling ═══════ */
Scrollbar {
    background: $surface;
    color: $accent;
}

ScrollbarCorner {
    background: $surface;
}

Scrollbar > .scrollbar--bar {
    color: $accent;
}

Scrollbar > .scrollbar--bar:hover {
    color: $primary;
}

Scrollbar > .scrollbar--bar:active {
    color: $warning;
}

/* ═══════ Selection ═══════ */
Screen > .screen--selection {
    background: $primary;
    color: $text;
}
```

---

## 38. Urutan implementasi styling (btop-inspired)

```
Phase A — Visual polish (CSS only, zero risk)
├── 1. Scrollbar styling (scrollbar-size, color, gutter)
├── 2. Panel border round + border_title
├── 3. :focus-within highlight
├── 4. :hover effect pada panels
└── 5. Scrollbar hover/active color change

Phase B — Tab Chat/File system (core feature)
├── 6. Buat FileView widget (list shared files per-peer)
├── 7. Buat ContentPanel container (holds ChatView + FileView)
├── 8. Tab switching logic (_switch_tab) + border_title update
├── 9. Per-peer file history storage
└── 10. Keyboard shortcut Ctrl+T untuk toggle tab

Phase C — Widget enhancement (minor code changes)
├── 11. border_title dynamic update (_refresh_panel_titles)
├── 12. Peer item hover/active styling
├── 13. Clickable tab buttons in panel header
└── 14. Clickable file items → open/show detail

Phase D — Layout restructure (compose() rewrite)
├── 15. Wrap sections dalam panel-box containers
├── 16. Responsive sidebar toggle (< 100 cols auto-hide)
├── 17. Three-column layout untuk 160+ cols
└── 18. Input box context switch (message input vs file send hint)

Phase E — Advanced interactions
├── 19. Clickable transfer progress → detail modal
├── 20. Status bar click → detail popup
├── 21. Drag-to-resize sidebar (stretch goal)
└── 22. File drag-and-drop support (stretch goal)
```

Phase A bisa dikerjakan tanpa mengubah behavior — hanya styling.
Phase B adalah fitur utama baru — pemisahan Chat dan File per-peer.
Phase C memerlukan perubahan kecil di Python.
Phase D memerlukan restrukturisasi `compose()` dan layout.
Phase E adalah fitur tambahan yang bisa ditunda.

---

## 39. Tab Chat / File — desain detail

> Konsep utama: area konten (di sebelah kanan sidebar) dibagi menjadi
> **dua tab** — Chat dan File. Kedua tab menempati **posisi yang sama**
> dan saling menggantikan. Ini **per-peer**, bukan global.

### Prinsip

- Setiap peer punya **chat history** dan **file list** sendiri.
- Saat switch peer di sidebar, tab yang aktif tetap sama (misal sedang
  di tab File, switch ke peer lain → tetap di tab File peer baru).
- Tab buttons ditampilkan di **border_title** panel konten.
- Tab yang aktif di-highlight bold+underline, tab tidak aktif di-dim.

### Tab Chat

Menampilkan percakapan chat dengan peer yang dipilih:

```
┌─ [Chat] File — Android ────────────────────────────────────────┐
│                                                                │▲
│ Baim                                                  14:32    │ │
│ Hello! Bisa kirim foto yang tadi?                              │ │
│                                                                │█│
│ Android                                               14:33    │█│
│ Oke, udah aku kirim ya.                                        │ │
│                                                                │ │
│ [System] File photo.jpg diterima (12.4 MB)                     │ │
│                                                                │▼│
├────────────────────────────────────────────────────────────────┤
│ > Type a message...                                            │
└────────────────────────────────────────────────────────────────┘
```

### Tab File

Menampilkan semua file yang pernah dikirim/diterima dengan peer tersebut.
File dikelompokkan jadi **ACTIVE** (transfer yang masih jalan) dan
**HISTORY** (selesai/gagal/ditolak) — supaya "masih berlangsung" nggak
kecampur sama "udah kelar" sekilas pandang. Tiap entri history juga
nunjukin badge mode penyimpanan (🔒 Secure / 📁 Normal — lihat
`SECURE_STORAGE_DESIGN.md` §5 soal kedua mode ini):

```
┌─ Chat [File] — Android ────────────────────────────────────────┐
│                                                                │▲
│ ACTIVE                                                         │ │
│ ↑ archive.zip          4.2 GB   ███████░ 63%  ETA 00:31        │ │
│                                                                │ │
│ HISTORY                                                        │█│
│ ↓ photo.jpg    🔒 Secure   12.4 MB   ✓ Received   14:33       │█│
│ ↓ document.pdf 📁 Normal    2.1 MB   ✓ Received   Yesterday   │ │
│                                                                │▼│
├────────────────────────────────────────────────────────────────┤
│ /send <filepath>                                Ctrl+C → Chat  │
└────────────────────────────────────────────────────────────────┘
```

### Mengklik file item — wajib lewat auth gate (Secure Storage)

**Klik item bukan langsung "open"** — itu keliru di draf sebelumnya.
Setiap aksi file (`SECURE_STORAGE_DESIGN.md` §4/§6) beda gerbangnya:

```
Klik file 🔒 Secure  → tampilkan menu aksi dulu:
                        [ Open ] [ Export ] [ Delete ]
                        → pilih salah satu → AUTH GATE (di bawah) → aksi jalan

Klik file 📁 Normal   → langsung buka lewat default app OS,
                        tanpa auth gate (bukan secure storage,
                        tidak ada yang perlu dibuka key-nya)

Transfer yang masih ACTIVE → klik → tampilkan detail progress modal,
                        bukan menu aksi file (belum ada file jadi
                        untuk dibuka)
```

Auth gate untuk Open/Export/Delete (belum termasuk Move to Secure
Storage, yang triggernya beda — dari sisi file *normal*, bukan dari tab
File ini):

```
┌─ 🔐 Authentication required ───────────────────┐
│                                                 │
│  laporan.pdf                                    │
│  Action: Export                                 │
│                                                 │
│  Enter passphrase:                              │
│  [••••••••••••••••]                             │
│                                                 │
│  ☐ Don't ask again this session (files only)   │
│                                                 │
│              [ Cancel ]        [ Continue ]     │
└─────────────────────────────────────────────────┘
```

- Kalau **Export** dan critical-action key udah di-set user (opsional,
  `SECURE_STORAGE_DESIGN.md` §11.7): setelah passphrase di-submit, modal
  ganti jadi minta critical-action key **secara berurutan** — bukan dua
  field sekaligus, karena keduanya digabung (HKDF), bukan dua kunci
  paralel.
- Checkbox "Don't ask again this session" cuma nongol kalau user belum
  nyalain itu; kalau session udah dalam mode "don't ask", modal ini
  di-skip sepenuhnya untuk Open/Export/Delete berikutnya sampai app
  di-lock lagi (§4).
- Modal ini harus tetap muat & kepake di hard floor 80×24 (§40) — nggak
  boleh didesain cuma buat layout comfortable.

### Mekanisme switching

```
User klik tab "File"        User klik tab "Chat"
        ↓                           ↓
chat-view.display = False   chat-view.display = True
file-view.display = True    file-view.display = False
        ↓                           ↓
border_title update         border_title update
input hint update           input hint update
```

Keyboard shortcuts:

```
Ctrl+T    Toggle antara Chat ↔ File
Ctrl+1    Langsung ke tab Chat
Ctrl+2    Langsung ke tab File
```

Mouse:

```
Klik "[Chat]" di border_title  → switch ke tab Chat
Klik "[File]" di border_title  → switch ke tab File
Klik file 🔒 Secure             → menu aksi [Open][Export][Delete] → auth gate
Klik file 📁 Normal             → buka langsung (no auth gate)
Klik transfer yang masih ACTIVE → detail progress modal
```

### Compose structure

```python
def compose(self) -> ComposeResult:
    yield Header(show_clock=True)
    with Horizontal(id="main"):
        yield ListView(id="peer-panel", classes="panel-box")
        with Vertical(id="content-panel", classes="panel-box"):
            # Kedua view menempati posisi yang sama
            # Hanya satu yang display=True pada satu waktu
            yield SelectableRichLog(id="chat-view", wrap=True, markup=True)
            yield ListView(id="file-view")
    yield Input(placeholder="Type a message...", id="input-box")
    yield Footer()
```

### Per-peer state

**Sumber data bukan cuma in-memory** — `shared_files` di-load dari tabel
`transfers` di vault terenkripsi (`SECURE_STORAGE_DESIGN.md` §12), bukan
state Python yang ilang tiap app ditutup. Struktur di bawah ini adalah
representasi in-memory buat rendering saat ini (sebuah cache/view, bukan
sumber kebenaran):

```python
@dataclass
class PeerContentState:
    peer_id: str
    chat_messages: list[dict]     # dari tabel `messages` (§12), di-load per-peer
    shared_files: list[dict]      # dari tabel `transfers` (§12), di-load per-peer
    active_tab: str = "chat"      # tab terakhir yang dibuka (bisa disimpan
                                   # di tabel `settings`, §12, biar persist
                                   # antar-restart juga — bukan cuma per sesi)
```

Alur load saat switch peer:

```
1. Simpan scroll position tab saat ini
2. Query tabel `messages` WHERE peer_device_id = peer_baru → chat_messages
3. Query tabel `transfers` WHERE peer_device_id = peer_baru → shared_files
   (memisahkan status: yang belum selesai jadi ACTIVE, sisanya HISTORY)
4. Restore tab yang terakhir aktif untuk peer tersebut
5. Restore scroll position
```

Konsekuensinya: vault harus dalam keadaan **unlocked** (§4 Secure
Storage) untuk tab Chat maupun tab File bisa nge-render apapun — kalau
locked, seluruh area konten (bukan cuma file) nunjukin state locked,
bukan cuma kosong.

### Perbedaan input box berdasarkan tab

Input box berubah hint berdasarkan tab aktif:

```
Tab Chat aktif:
  placeholder: "Type a message, or /help for commands"
  Enter → kirim chat message

Tab File aktif:
  placeholder: "/send <filepath> to share a file"
  Enter → /send command (auto-prefix jika bukan slash command)
```

Ini membuat UX lebih intuitif — user tidak perlu menghafal command
untuk kirim file saat sudah berada di tab File.

---

## 40. Terminal size — paksa atau adaptif?

> Diskusi desain: apakah peerc harus memaksakan ukuran terminal minimum,
> atau membiarkan user bebas pakai ukuran apa saja?

### Opsi A: Paksa minimum size

User **harus** menggunakan terminal minimal ukuran tertentu (misalnya
100×30). Kalau terminal lebih kecil, tampilkan pesan error:

```
┌──────────────────────────────────────┐
│                                      │
│   Terminal terlalu kecil.            │
│                                      │
│   Minimum: 100 × 30                  │
│   Saat ini: 80 × 24                  │
│                                      │
│   Perbesar terminal untuk            │
│   melanjutkan.                       │
│                                      │
└──────────────────────────────────────┘
```

**Kelebihan:**

- UI **selalu terlihat sempurna** — sidebar, chat, file tab, transfer
  panel semuanya tampil penuh.
- Tidak perlu membuat banyak responsive breakpoint.
- Testing lebih mudah — hanya satu layout yang perlu diuji.
- Pengalaman visual **konsisten** di semua user.
- Scrollbar, panel boxes, tab buttons selalu punya ruang yang cukup.

**Kekurangan:**

- **Memaksa user** — kalau terminal default mereka 80×24 (sangat umum),
  mereka harus resize manual sebelum bisa pakai peerc.
- **SSH session** sering kali kecil (80×24 atau bahkan lebih kecil).
- **Tmux/screen split pane** bisa jauh lebih kecil dari 100 cols.
- **Mobile terminal** (Termux, iSH) biasanya sangat kecil.
- User yang split terminal di tiling WM (i3, sway, bspwm) sering
  hanya punya setengah layar.
- Kesan **tidak ramah** — user langsung disambut pesan error.

### Opsi B: Fully adaptive (tanpa minimum)

UI menyesuaikan diri ke ukuran apa pun, termasuk 40×10.

**Kelebihan:**

- User **tidak pernah diblokir** — peerc selalu bisa digunakan.
- Bekerja di mana saja: SSH, tmux split, Termux, tiling WM.
- Terasa **profesional** — seperti vim yang bisa di-resize ke apa saja.

**Kekurangan:**

- Di ukuran sangat kecil, UI **tidak berguna** — text terpotong,
  scrollbar hilang, panel tumpuk-tumpuk.
- Perlu banyak responsive breakpoint dan edge case handling.
- Testing jauh lebih kompleks.
- Pengalaman visual **inkonsisten** — user di terminal kecil melihat
  versi "cacat" dari app.

### Opsi C: Hybrid — minimum floor + graceful degradation (DIPILIH)

Ini pendekatan yang dipakai btop, htop, dan kebanyakan TUI modern:

```
< 80×24     → "Terminal too small" overlay (hard floor)
80×24       → Minimal usable layout (chat only, no sidebar)
100×30      → Standard layout (sidebar + chat/file tabs)
120×40      → Comfortable layout (sidebar + chat/file + transfers)
160×50      → Full layout (three-column + all panels)
```

**Mengapa hybrid:**

1. **Hard floor kecil (80×24)** — ini ukuran terminal klasik yang
   hampir semua terminal support. Di bawah ini, TUI apa pun tidak
   berguna. Menampilkan pesan "terminal too small" di sini wajar
   dan user tidak merasa dipaksa.

2. **Graceful degradation di atas floor** — di 80×24 user masih bisa
   chat dan kirim file, hanya tanpa sidebar. Di 100+ mereka dapat
   full experience. Tidak ada yang dipaksa.

3. **Pengalaman terbaik tetap available** — user yang resize ke 120+
   mendapat full btop-style layout.

### Detail implementasi

```python
def on_resize(self, event: Resize) -> None:
    """Handle terminal resize dengan graceful degradation."""
    w, h = event.size

    # Hard floor — tampilkan overlay
    if w < 80 or h < 24:
        self._show_too_small_overlay(w, h, min_w=80, min_h=24)
        return
    self._hide_too_small_overlay()

    # Adaptive layout
    sidebar = self.query_one("#peer-panel")
    info_panel = self.query_one("#info-panel", default=None)

    if w < 100:
        # Compact: sidebar hidden
        sidebar.display = False
        if info_panel:
            info_panel.display = False
    elif w < 160:
        # Standard: sidebar + content
        sidebar.display = True
        sidebar.styles.width = 28
        if info_panel:
            info_panel.display = False
    else:
        # Wide: sidebar + content + info
        sidebar.display = True
        sidebar.styles.width = 32
        if info_panel:
            info_panel.display = True
```

"Too small" overlay:

```python
class TooSmallOverlay(Widget):
    """Overlay yang tampil saat terminal di bawah minimum."""

    def __init__(self, current_w: int, current_h: int,
                 min_w: int, min_h: int):
        super().__init__()
        self.current_w = current_w
        self.current_h = current_h
        self.min_w = min_w
        self.min_h = min_h

    def render(self) -> str:
        return (
            f"Terminal terlalu kecil.\n\n"
            f"Minimum : {self.min_w} × {self.min_h}\n"
            f"Saat ini: {self.current_w} × {self.current_h}\n\n"
            f"Perbesar terminal untuk melanjutkan."
        )
```

### Perbandingan dengan app lain

```
App         Hard Floor   Degradation           Resize
─────────   ──────────   ────────────────────   ─────────
btop        80×24        Hide panels, reduce    Real-time
htop        ~80×16       Truncate columns       Real-time
lazygit     ~80×20       Collapse panels        Real-time
vim/nvim    Tidak ada    Selalu adaptif         Real-time
peerc       80×24        Hide sidebar, tabs     Real-time
```

### Breakpoint final

```
Width       Layout
─────────   ──────────────────────────────────────────────
< 80        ✕ "Terminal too small"
80-99       Chat/File only, no sidebar, status bar hint
100-119     Sidebar (compact 24) + Chat/File tabs
120-159     Sidebar (28) + Chat/File tabs + transfer bar
160+        Sidebar (32) + Chat/File tabs + device info panel
```

```
Height      Behavior
─────────   ──────────────────────────────────────────────
< 24        ✕ "Terminal too small"
24-29       Input box 1 line, no transfer panel
30-39       Input box 1 line, transfer panel 2 lines
40+         Full layout, transfer panel expandable
```

### Keputusan

**Opsi C (Hybrid)** dipilih karena:

- Hard floor 80×24 sangat rendah — hampir tidak ada user yang akan
  terkena blokir ini.
- Graceful degradation membuat peerc **usable di mana saja**: SSH,
  tmux, tiling WM, Termux.
- User yang mau **pengalaman terbaik** cukup maximize terminal atau
  pakai ≥120×30 — mereka dapat full btop-style layout.
- Ini standar industri — btop, htop, lazygit semua melakukan hal
  yang sama.

Jadi user **tidak dipaksa**, tetapi user yang pakai terminal besar
**mendapat pengalaman yang lebih kaya**. Sebaliknya, user di terminal
kecil tetap bisa pakai peerc tanpa diblokir — hanya layout yang
lebih sederhana.

---

## 41. In-App File Viewer — Document, Media, Text

> Dokumen spesifikasi arsitektur lengkap: [`FILE_VIEWER_DESIGN.md`](./FILE_VIEWER_DESIGN.md)

Untuk mendukung eksplorasi file yang dibagikan antar-peer dan file di dalam
Secure Storage tanpa membocorkan cache plaintext ke filesystem OS
(mitigasi `SECURE_STORAGE_DESIGN.md` §10), `peerc` mengintegrasikan
file viewer berbasis in-memory streaming dengan 3 kategori:

```
┌────────────────────────────────────────────────────────────┐
│ [Esc / q] Tutup Viewer       proposal_draft.pdf (Hal 2/14) │
├────────────────────────────────────────────────────────────┤
│                                                            │
│  ## Executive Summary                                      │
│                                                            │
│  Sistem transfer P2P berbasis enkripsi ChaCha20-Poly1305   │
│  dengan authenticated handshake Ed25519 + X25519.          │
│                                                            │
│  ┌───────────────────────────────┐                         │
│  │ [Diagram Arsitektur Visual]   │                         │
│  │ (Rendered via Kitty/Halfblock)│                         │
│  └───────────────────────────────┘                         │
│                                                            │
├────────────────────────────────────────────────────────────┤
│ [n] Next Page  [p] Prev Page  [j/k] Scroll  [Ctrl+O] Open  │
└────────────────────────────────────────────────────────────┘
```

### 1. Kategori & Stack Open-Source

1. **Text & Code** (`.txt`, `.py`, `.md`, `.json`, `.csv`, `.log`):
   - **Markdown**: Textual native `MarkdownViewer` (TOC otomatis + link navigasi).
   - **Syntax Highlighting**: `rich.syntax.Syntax` + Pygments (nomor baris + tema konsisten).
   - **Data Tabular**: Textual `DataTable` (CSV/TSV grid).
   - **External Pager**: `bat` melalui `stdin` anonymous pipe (`bat --paging=always -`).

2. **Media** (Gambar, Audio, Video):
   - **Image** (`.png`, `.jpg`, `.webp`, `.gif`):
     - In-memory `Pillow` + Textual canvas viewer.
     - Auto-detect protokol emulator: **Kitty Graphics Protocol** / **Sixel** untuk resolusi penuh, atau fallback universal ke **ANSI Truecolor Half-blocks** (`▀`, `▄`).
     - Tool CLI: `chafa -` atau `viu -` via `stdin`.
   - **Audio** (`.mp3`, `.wav`, `.flac`, `.ogg`):
     - In-memory decoding: Python `miniaudio`.
     - Headless streaming: `mpv --no-video -` dengan IPC socket untuk kontrol play/pause/timeline.
   - **Video** (`.mp4`, `.webm`):
     - Thumbnail poster extraction in-memory + streaming playback via `mpv -`.

3. **Document** (`.pdf`, `.epub`, `.docx`, `.xlsx`):
   - **PDF & EPUB**:
     - Engine utama: [`PyMuPDF`](https://github.com/pymupdf/PyMuPDF) (`fitz`).
     - Dibaca langsung dari `stream=decrypted_bytes` di RAM.
     - Dual mode: **Text Mode** (ekstraksi teks Markdown per-halaman) dan **Visual Mode** (render raster pixmap ke image engine).
   - **Spreadsheet (`.xlsx`)**:
     - `openpyxl` stream -> Textual `DataTable` atau integrasi TUI [`VisiData`](https://www.visidata.org/).

### 2. Keamanan: Zero Disk Footprint

- **100% In-Memory**: Data terdekripsi dari Secure Storage tidak pernah
  disimpan ke file disk biasa saat di-preview.
- **Anonymous Pipe**: External CLI tools (`bat`, `chafa`, `mpv`) hanya
  menerima stream data melalui `sys.stdin` pipe, mencegah kebocoran
  ke recent files atau temporary storage OS.


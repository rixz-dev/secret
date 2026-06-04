```markdown
# SECRET-2.0 — CIPHER TERMINAL

> Multi-layer encryption tool for secure messaging.  
> Built by **rixz-dev (reiz_riz)** · Cryptographic core by **FU4Dxx28X**

---

## Tentang

SECRET-2.0 adalah terminal enkripsi pesan dengan 3 layer kriptografi independen:

- **AES-256-GCM** — NIST standard, hardware accelerated
- **ChaCha20-Poly1305** — immune to timing attacks
- **XSalsa20-Poly1305** — 192-bit nonce via libsodium

Setiap enkripsi menghasilkan key unik yang tidak akan pernah sama dua kali.

---

## Instalasi di Termux

```bash
# Update package
pkg update && pkg upgrade

# Install Python
pkg install python

# Install dependencies
pip install pycryptodome pynacl blessed yachalk pyfiglet

# Opsional — QR code support
pip install qrcode

# Clone / copy script ke device
# Letakkan script di folder yang mudah diakses, misal:
mkdir -p ~/secret2
cp secret2.py ~/secret2/
cd ~/secret2
```

Jalankan:

```bash
# Mode TUI (menu interaktif)
python secret2.py

# Mode CLI one-liner
python secret2.py enc "pesan rahasia lo"
python secret2.py dec "CIPHERTEXT" --key "KEYSTRING"
```

---

## Cara Pakai

### Enkripsi Pesan

1. Jalankan `python secret2.py`
2. Pilih **encrypt** dari menu
3. Ketik pesan yang ingin dienkripsi
4. Script menghasilkan dua output:
   - **CIPHER** — teks panjang berisi pesan terenkripsi
   - **KEY** — kunci untuk mendekripsi

### Dekripsi Pesan

1. Jalankan `python secret2.py`
2. Pilih **decrypt** dari menu
3. Masukkan KEY yang diterima
4. Paste CIPHER yang diterima
5. Pesan asli ditampilkan

---

## Aturan Pengiriman

```
CIPHER  → boleh dikirim ke mana saja (grup, publik, dll)
KEY     → hanya dikirim PRIVAT ke rekan yang dituju
```

Tanpa KEY, CIPHER tidak ada artinya bagi siapa pun.

### Contoh Alur

```
Situasi: A ingin menyampaikan sesuatu ke B di dalam grup


[ A ]  encrypt pesan
         │
         ├── CIPHER ──→ kirim ke GRUP (publik, aman)
         │
         └── KEY ─────→ kirim ke DM si B (privat)


[ B ]  terima cipher dari grup + key dari DM
         │
         └── decrypt → baca pesan asli


[ Semua orang lain di grup ]
         │
         └── lihat cipher → tidak bisa baca apa-apa tanpa key
```

### Contoh Nyata

**A di grup:**
```
@B — 4F3A9C2B1E....(cipher panjang)....8D7F
```

**A ke DM B:**
```
key: Hl4$mK9....(key string)....Xp2@
```

**B jalankan decrypt** → baca pesan.

---

## Aturan Wajib

1. **KEY tidak boleh bocor ke publik** — siapapun yang punya key bisa baca pesan
2. **Satu key = satu pesan** — setiap enkripsi menghasilkan key baru, jangan reuse
3. **Key dan cipher tidak boleh dikirim dalam satu channel yang sama** — kalau cipher di grup, key di DM. Kalau cipher di DM, key di channel lain
4. **Key jangan di-screenshot dan di-share** ke selain rekan yang dituju
5. **Setelah pesan dibaca**, key bisa dihapus — cipher tanpa key = sampah

---

## Kolaborasi

| Role | Handle |
|---|---|
| UI/UX Architect | rixz-dev (reiz_riz) |
| Cryptographic Core Engineer | FU4Dxx28X |

---

## Catatan Teknis

- Key adalah 120 bytes pure random → keyspace 2^960 → tidak bisa di-brute-force
- Setiap layer punya key dan nonce independen
- Ciphertext melewati 4 encoding pass (zlib → base85 → base32 → hex) sebelum ditampilkan
- Tidak ada server, tidak ada telemetri — semua proses lokal di device
```

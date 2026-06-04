#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════════╗
# ║                  SECRET-2.0 — CIPHER TERMINAL                ║
# ║                                                              ║
# ║  UI/UX Architect          : rixz-dev (reiz_riz)              ║
# ║  Cryptographic Core Eng.  : FU4Dxx28X                        ║
# ╚══════════════════════════════════════════════════════════════╝

import base64, nacl, time, sys, os, io, json, math, hashlib, zlib
import argparse, getpass, subprocess
import nacl.exceptions
from nacl import secret, utils
from blessed import terminal
from yachalk import chalk
from pyfiglet import figlet_format as format
from collections import Counter
from datetime import datetime
from Crypto.Cipher import AES as _AES, ChaCha20_Poly1305 as _ChaCha

# ─── CONFIG ───────────────────────────────────────────────────────────────────

CONFIG_PATH  = os.path.expanduser("~/.secret2_config.json")
KEYS_DIR     = os.path.expanduser("~/.secret2_keys")
HISTORY_PFX  = "secret2_history"
DEBUG        = os.environ.get("SECRET2_DEBUG", "0") == "1"

THEMES = {
    "green": {
        "primary": chalk.green.bold,
        "accent" : chalk.green,
        "sep"    : chalk.grey.bold,
        "warn"   : chalk.yellow.bold,
        "info"   : chalk.cyan,
        "error"  : chalk.red.bold,
    },
    "cyan": {
        "primary": chalk.cyan.bold,
        "accent" : chalk.cyan,
        "sep"    : chalk.blue.bold,
        "warn"   : chalk.yellow.bold,
        "info"   : chalk.white,
        "error"  : chalk.red.bold,
    },
    "amber": {
        "primary": chalk.yellow.bold,
        "accent" : chalk.yellow,
        "sep"    : chalk.white.bold,
        "warn"   : chalk.red,
        "info"   : chalk.green,
        "error"  : chalk.red.bold,
    },
}

def load_config() -> dict:
    try:
        with open(CONFIG_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return {"theme": "green"}

def save_config(cfg: dict):
    try:
        with open(CONFIG_PATH, "w") as f:
            json.dump(cfg, f)
    except Exception:
        pass

def get_theme(cfg: dict) -> dict:
    return THEMES.get(cfg.get("theme", "green"), THEMES["green"])


# ─── CORE CRYPTO ──────────────────────────────────────────────────────────────
#
#  ENCRYPTION LAYERS (innermost → outermost):
#    L1  zlib compress     — size reduction + plaintext structure destruction
#    L2  AES-256-GCM       — NIST standard AEAD, hardware accelerated
#    L3  ChaCha20-Poly1305 — modern AEAD, immune to timing attacks
#    L4  XSalsa20-Poly1305 — PyNaCl, 192-bit nonce, MAC embedded
#
#  ENCODING LAYERS (applied to final ciphertext blob):
#    E1  zlib compress (level=1) — structural pattern elimination
#    E2  Base85               — binary-to-ASCII, compact
#    E3  Base32               — second alphabet layer
#    E4  Hex (uppercase)      — final printable cipher string
#
#  KEY FORMAT:
#    k1 (32B) + n1 (12B) + k2 (32B) + n2 (12B) + k3 (32B) = 120 bytes
#    → base64.a85encode → printable ASCII key string (~150 chars)
#
#  ATTACK SURFACE:
#    Brute-force: need all 3 keys simultaneously (3 × 256-bit keyspace)
#    Ciphertext-only: zero structure after 4 encoding passes
#    Known-plaintext: blocked by random k1/k2/k3 + 3 independent nonces
#    Quantum (Grover): AES-256 halved to 128-bit effective — still secure
#

def encrypt(text: str) -> tuple:
    raw = text.encode("utf-8")

    # Layer 1: zlib — destroy plaintext structure before any encryption
    raw = zlib.compress(raw, level=9)

    # Layer 2: AES-256-GCM (pycryptodome)
    k1   = os.urandom(32)
    n1   = os.urandom(12)
    _aes = _AES.new(k1, _AES.MODE_GCM, nonce=n1)
    _c1_data, _tag1 = _aes.encrypt_and_digest(raw)
    c1 = _c1_data + _tag1  # ciphertext + 16B tag — same layout as cryptography

    # Layer 3: ChaCha20-Poly1305 (pycryptodome)
    k2  = os.urandom(32)
    n2  = os.urandom(12)
    _cc = _ChaCha.new(key=k2, nonce=n2)
    _c2_data, _tag2 = _cc.encrypt_and_digest(c1)
    c2 = _c2_data + _tag2  # ciphertext + 16B tag

    # Layer 4: XSalsa20-Poly1305 (PyNaCl, 192-bit nonce embedded)
    k3  = utils.random(secret.SecretBox.KEY_SIZE)
    c3  = secret.SecretBox(k3).encrypt(c2)

    # Encoding pass 1: zlib (post-crypto — eliminates any residual patterns)
    e1 = zlib.compress(c3, level=1)
    # Encoding pass 2: Base85
    e2 = base64.b85encode(e1)
    # Encoding pass 3: Base32
    e3 = base64.b32encode(e2)
    # Encoding pass 4: Hex → final cipher string
    cipher_str = e3.hex().upper()

    # Pack all key material into one printable string
    # k1(32) + n1(12) + k2(32) + n2(12) + k3(32) = 120 bytes
    key_str = base64.a85encode(k1 + n1 + k2 + n2 + k3).decode()

    return cipher_str, key_str


def decrypt(text: str, key: str) -> str:
    # Unpack key material
    raw_key = base64.a85decode(key)
    if len(raw_key) != 120:
        raise ValueError("Key tidak valid: panjang tidak sesuai")
    k1 = raw_key[0:32]
    n1 = raw_key[32:44]
    k2 = raw_key[44:76]
    n2 = raw_key[76:88]
    k3 = raw_key[88:120]

    # Peel encoding layers (reverse order)
    try:
        e3 = bytes.fromhex(text)
    except ValueError:
        raise ValueError("Cipher bukan hex valid")
    e2 = base64.b32decode(e3)
    e1 = base64.b85decode(e2)
    c3 = zlib.decompress(e1)

    # Peel Layer 4: XSalsa20-Poly1305 (PyNaCl)
    try:
        c2 = secret.SecretBox(k3).decrypt(c3)
    except nacl.exceptions.CryptoError:
        raise ValueError("Auth gagal: layer XSalsa20 (key salah atau data corrupt)")

    # Peel Layer 3: ChaCha20-Poly1305 (pycryptodome)
    try:
        c2_data, tag2 = c2[:-16], c2[-16:]
        _cc = _ChaCha.new(key=k2, nonce=n2)
        c1 = _cc.decrypt_and_verify(c2_data, tag2)
    except Exception:
        raise ValueError("Auth gagal: layer ChaCha20 (key salah atau data corrupt)")

    # Peel Layer 2: AES-256-GCM (pycryptodome)
    try:
        c1_data, tag1 = c1[:-16], c1[-16:]
        _aes = _AES.new(k1, _AES.MODE_GCM, nonce=n1)
        raw = _aes.decrypt_and_verify(c1_data, tag1)
    except Exception:
        raise ValueError("Auth gagal: layer AES-GCM (key salah atau data corrupt)")

    # Decompress
    return zlib.decompress(raw).decode("utf-8")


# ─── UTILITIES ────────────────────────────────────────────────────────────────

def typewriter(text: str, delay: float = 0.03):
    for c in text:
        print(c, end="", flush=True)
        time.sleep(delay)
    print()

def scanline_clear(t, theme: dict):
    rows  = min(t.height or 24, 16)
    width = t.width or 80
    bar   = "░▒▓█▓▒░" * (width // 7 + 1)
    for row in range(rows):
        sys.stdout.write(t.move(row, 0))
        sys.stdout.write(theme["primary"](bar[:width]))
        sys.stdout.flush()
        time.sleep(0.009)
    time.sleep(0.04)
    print(t.home + t.clear)

def draw_box(t, theme: dict, items: list):
    width   = t.width or 80
    lbl_w   = max((len(lbl) for lbl, _ in items), default=6)
    inner_w = min(width - 4, max((len(f"  {l:<{lbl_w}} | {v}  ") for l, v in items), default=20))

    print(theme["primary"]("╔" + "═" * inner_w + "╗"))
    for lbl, val in items:
        line = f"  {lbl:<{lbl_w}} │ {val}"
        if len(line) > inner_w:
            line = line[:inner_w - 3] + "..."
        print(theme["primary"](f"║{line:<{inner_w}}║"))
    print(theme["primary"]("╚" + "═" * inner_w + "╝"))

def key_fingerprint(key: str) -> str:
    h = hashlib.sha256(key.encode()).hexdigest()[:8].upper()
    return f"{h[:4]}-{h[4:]}"

def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counter = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counter.values())

def entropy_bar(text: str, width: int = 20) -> tuple:
    ent     = shannon_entropy(text)
    charset = max(len(set(text)), 2)
    max_e   = math.log2(charset)
    pct     = min(ent / max_e if max_e > 0 else 0, 1.0)
    filled  = int(pct * width)
    bar     = "█" * filled + "░" * (width - filled)
    level   = "rendah" if pct < 0.4 else "cukup" if pct < 0.7 else "tinggi"
    return pct, bar, ent, level

def validate_key_format(key: str) -> tuple:
    if not key.strip():
        return False, "key tidak boleh kosong"
    return True, "ok"

def copy_to_clipboard(text: str) -> bool:
    try:
        result = subprocess.run(
            ["termux-clipboard-set"], input=text.encode(),
            capture_output=True, timeout=2
        )
        if result.returncode == 0:
            return True
    except Exception:
        pass
    try:
        import pyperclip
        pyperclip.copy(text)
        return True
    except Exception:
        return False

def masked_input(t, prompt: str) -> str:
    print(prompt, end="", flush=True)
    buf = []
    with t.cbreak():
        while True:
            ch = t.inkey()
            if ch.name in ("KEY_ENTER",) or str(ch) in ("\n", "\r"):
                break
            elif ch.name in ("KEY_BACKSPACE", "KEY_DELETE") or str(ch) == "\x7f":
                if buf:
                    buf.pop()
                    sys.stdout.write("\b \b")
                    sys.stdout.flush()
            elif not ch.is_sequence and str(ch).isprintable():
                buf.append(str(ch))
                sys.stdout.write("*")
                sys.stdout.flush()
    print()
    return "".join(buf)

def secure_clear(label: str):
    sys.stdout.write("\r" + " " * (len(label) + 30) + "\r")
    sys.stdout.flush()

def show_debug_panel(theme: dict):
    if not DEBUG:
        return
    try:
        import nacl.version as nv
        ver = nv.VERSION
    except Exception:
        ver = "?"
    line = (
        f"[DEBUG] PyNaCl {ver}  "
        f"KEY={secret.SecretBox.KEY_SIZE}B  "
        f"NONCE={secret.SecretBox.NONCE_SIZE}B  "
        f"MAC={secret.SecretBox.MACBYTES}B"
    )
    print(theme["info"](line))

def show_qr(cipher: str, theme: dict):
    try:
        import qrcode
        qr = qrcode.QRCode(border=1)
        qr.add_data(cipher)
        qr.make(fit=True)
        buf = io.StringIO()
        qr.print_ascii(out=buf, invert=True)
        print(theme["accent"](buf.getvalue()))
    except ImportError:
        print(theme["warn"]("[!] install qrcode dulu: pip install qrcode"))
    except Exception as e:
        print(theme["error"](f"[!] QR error: {e}"))

def get_multiline_input(prompt: str) -> str:
    line = input(f"\n[+] {prompt} (atau ::multi untuk multi-baris): ").strip()
    if line == "::multi":
        print("[+] mode multi-baris — baris kosong untuk selesai:")
        lines = []
        while True:
            l = input()
            if l == "":
                break
            lines.append(l)
        return "\n".join(lines)
    return line


# ─── HISTORY ──────────────────────────────────────────────────────────────────

def save_history(entry: dict):
    date_str = datetime.now().strftime("%Y-%m-%d")
    filename = f"{HISTORY_PFX}_{date_str}.txt"
    with open(filename, "a", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write(f"Tanggal  : {entry.get('date', '-')}\n")
        f.write(f"Waktu    : {entry.get('time', '-')}\n")
        f.write(f"Tipe     : {entry.get('type', '-').upper()}\n")
        if entry.get("original"):
            f.write(f"Pesan    : {entry['original']}\n")
        if entry.get("key"):
            f.write(f"Key      : {entry['key']}\n")
        if entry.get("cipher"):
            f.write(f"Cipher   : {entry['cipher']}\n")
        if entry.get("result"):
            f.write(f"Hasil    : {entry['result']}\n")
        f.write("=" * 60 + "\n\n")


def show_session_history(t, session_log: list, theme: dict):
    if not session_log:
        print(t.home + t.clear)
        print(theme["warn"]("[!] session history kosong"))
        time.sleep(1.2)
        return

    idx = 0
    while True:
        print(t.home + t.clear)
        print(theme["primary"]("[ SESSION HISTORY ]"))
        print(theme["sep"]("─" * (t.width or 60)))
        entry = session_log[idx]
        print(theme["accent"](f"  {idx + 1} / {len(session_log)}"))
        print(f"  Waktu   : {entry.get('time', '-')}")
        print(f"  Tipe    : {entry.get('type', '-').upper()}")
        print(f"  Preview : {entry.get('preview', '-')}")
        cipher = entry.get("cipher", "")
        if cipher:
            preview_c = cipher[:50] + ("..." if len(cipher) > 50 else "")
            print(f"  Cipher  : {preview_c}")
        key_val = entry.get("key", "")
        if key_val:
            print(f"  Key FP  : {key_fingerprint(key_val)}")
        if entry.get("result"):
            print(f"  Hasil   : {entry['result'][:40]}...")
        print(theme["sep"]("─" * (t.width or 60)))
        print(theme["info"]("  ↑↓ navigate  |  ESC kembali"))
        with t.cbreak():
            k = t.inkey()
            if k.name == "KEY_UP":
                idx = (idx - 1) % len(session_log)
            elif k.name == "KEY_DOWN":
                idx = (idx + 1) % len(session_log)
            elif k.name == "KEY_ESCAPE":
                break


# ─── SETTINGS ─────────────────────────────────────────────────────────────────

def show_settings(t, cfg: dict) -> dict:
    theme_list = list(THEMES.keys())
    si = theme_list.index(cfg.get("theme", "green"))

    while True:
        theme = get_theme(cfg)
        print(t.home + t.clear)
        print(theme["primary"]("[ SETTINGS ]"))
        print(theme["sep"]("─" * (t.width or 60)))
        print(theme["info"]("  TEMA:"))
        for i, name in enumerate(theme_list):
            marker = "▶" if i == si else " "
            line = f"  {marker}  {name}"
            print(theme["primary"](line) if i == si else theme["accent"](line))
        print(theme["sep"]("─" * (t.width or 60)))
        print(theme["info"]("  ↑↓ pilih  |  Enter simpan  |  ESC batal"))
        with t.cbreak():
            k = t.inkey()
            if k.name == "KEY_UP":
                si = (si - 1) % len(theme_list)
                cfg["theme"] = theme_list[si]
            elif k.name == "KEY_DOWN":
                si = (si + 1) % len(theme_list)
                cfg["theme"] = theme_list[si]
            elif k.name == "KEY_ENTER":
                save_config(cfg)
                print(theme["primary"]("\n[✓] tema disimpan"))
                time.sleep(0.8)
                break
            elif k.name == "KEY_ESCAPE":
                break
    return cfg


# ─── SAVE KEY WITH MASTER PASSWORD ────────────────────────────────────────────

def save_key_with_password(cipher: str, key: str, ts: str, theme: dict):
    try:
        password = getpass.getpass("\n[+] master password untuk simpan key: ")
        if not password:
            print(theme["warn"]("[!] password kosong — skip"))
            return
        pw_key  = hashlib.sha256(password.encode()).digest()
        box     = secret.SecretBox(pw_key)
        enc_key = box.encrypt(key.encode())
        enc_b85 = base64.a85encode(enc_key).decode()
        os.makedirs(KEYS_DIR, exist_ok=True)
        path = os.path.join(KEYS_DIR, f"{ts}.bin")
        with open(path, "w") as f:
            json.dump({"cipher": cipher, "encrypted_key": enc_b85, "ts": ts}, f)
        print(theme["primary"](f"[✓] key disimpan: {path}"))
    except Exception as e:
        print(theme["error"](f"[!] gagal simpan: {e}"))


# ─── ENCRYPT HANDLER ──────────────────────────────────────────────────────────

def handle_encrypt(t, theme: dict, session_log: list):
    print(t.home + t.clear)
    pesan = get_multiline_input("masukkan pesan")
    if not pesan:
        print(theme["warn"]("[!] pesan tidak boleh kosong"))
        time.sleep(1.2)
        return

    pct, bar, ent_val, level = entropy_bar(pesan)
    print(theme["info"](f"\nentropi  [{bar}] {pct*100:.0f}%  —  {level}  ({ent_val:.2f} bits/char)"))

    preview = pesan[:60] + ("..." if len(pesan) > 60 else "")
    print(theme["accent"](f'\nPreview: "{preview}"  ({len(pesan)} chars)'))
    print(theme["info"]("[Enter] lanjut  |  [q] batal"))
    with t.cbreak():
        c = t.inkey()
        if str(c).lower() == "q":
            return

    cipher, key = encrypt(pesan)
    fp  = key_fingerprint(key)
    now = datetime.now()

    print(theme["accent"](f"\npesan rahasia: ") + cipher)
    print(theme["accent"](f"\nkey: ") + key)
    print(theme["info"](f"\nfingerprint: {fp}"))

    print(theme["info"]("\n[C] copy cipher  [K] copy key  [B] copy both  [Q] QR  [S] simpan key  [Enter] skip"))
    with t.cbreak():
        ch = str(t.inkey()).lower()
        if ch == "c":
            ok = copy_to_clipboard(cipher)
            print(theme["primary"]("[✓] cipher disalin" if ok else "[!] clipboard gagal"))
            time.sleep(0.7)
        elif ch == "k":
            ok = copy_to_clipboard(key)
            print(theme["primary"]("[✓] key disalin" if ok else "[!] clipboard gagal"))
            time.sleep(0.7)
        elif ch == "b":
            ok = copy_to_clipboard(f"CIPHER: {cipher}\nKEY: {key}")
            print(theme["primary"]("[✓] keduanya disalin" if ok else "[!] clipboard gagal"))
            time.sleep(0.7)
        elif ch == "q":
            show_qr(cipher, theme)
            input(theme["info"]("\nTekan Enter..."))
        elif ch == "s":
            save_key_with_password(cipher, key, now.strftime("%Y%m%d_%H%M%S"), theme)
            time.sleep(1.0)

    entry = {
        "type"    : "enc",
        "date"    : now.strftime("%Y-%m-%d"),
        "time"    : now.strftime("%H:%M:%S"),
        "original": pesan,
        "key"     : key,
        "cipher"  : cipher,
        "result"  : "",
        "preview" : pesan[:30] + ("..." if len(pesan) > 30 else ""),
    }
    session_log.append(entry)
    save_history(entry)
    input(theme["info"]("\nTekan Enter..."))


# ─── DECRYPT HANDLER ──────────────────────────────────────────────────────────

def handle_decrypt(t, theme: dict, session_log: list):
    print(t.home + t.clear)

    key = masked_input(t, "\n[+] masukkan secret key (hidden): ")
    if not key:
        print(theme["warn"]("[!] key tidak boleh kosong"))
        time.sleep(1.2)
        return

    valid, msg = validate_key_format(key)
    if not valid:
        print(theme["error"](f"[!] {msg}"))
        time.sleep(1.5)
        return

    fp = key_fingerprint(key)
    print(theme["info"](f"[✓] format key valid  |  fingerprint: {fp}"))

    cipher = input("\n[+] paste pesan rahasia: ").strip()
    if not cipher:
        print(theme["warn"]("[!] pesan rahasia tidak boleh kosong"))
        time.sleep(1.2)
        return

    try:
        result = decrypt(cipher, key)
    except (ValueError, Exception) as e:
        err = str(e).lower()
        if any(x in err for x in ("mac", "crypt", "invalid", "corrupt", "decode", "auth")):
            print(theme["error"]("[!] key valid tapi pesan corrupt atau tidak cocok"))
        else:
            print(theme["error"](f"[!] decrypt gagal: {e}"))
        time.sleep(1.5)
        return

    now = datetime.now()
    print(theme["primary"](f"\n[✓] pesan: {result}"))
    print(theme["info"]("\n[Enter] lanjut (pesan akan di-clear)"))
    input()
    secure_clear(result)

    entry = {
        "type"    : "dec",
        "date"    : now.strftime("%Y-%m-%d"),
        "time"    : now.strftime("%H:%M:%S"),
        "original": "",
        "key"     : key,
        "cipher"  : cipher,
        "result"  : result,
        "preview" : result[:30] + ("..." if len(result) > 30 else ""),
    }
    session_log.append(entry)
    save_history(entry)


# ─── FILE ENCRYPT HANDLER ─────────────────────────────────────────────────────

def handle_file_encrypt(t, theme: dict, session_log: list):
    print(t.home + t.clear)
    path = input("\n[+] path file yang mau dienkripsi: ").strip()
    if not path or not os.path.isfile(path):
        print(theme["error"]("[!] file tidak ditemukan"))
        time.sleep(1.5)
        return

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except Exception as e:
        print(theme["error"](f"[!] gagal baca file: {e}"))
        time.sleep(1.5)
        return

    if not content.strip():
        print(theme["warn"]("[!] file kosong"))
        time.sleep(1.5)
        return

    cipher, key = encrypt(content)
    fp = key_fingerprint(key)

    out_c = path + ".enc"
    out_k = path + ".key"

    with open(out_c, "w") as fc:
        fc.write(cipher)
    with open(out_k, "w") as fk:
        fk.write(key)

    draw_box(t, theme, [
        ("CIPHER FILE", out_c),
        ("KEY FILE",    out_k),
        ("FINGERPRINT", fp),
        ("ALGORITHM",   "AES-GCM + ChaCha20 + XSalsa20"),
        ("INPUT SIZE",  f"{len(content)} chars"),
        ("CIPHER SIZE", f"{len(cipher)} bytes"),
    ])

    now = datetime.now()
    entry = {
        "type"    : "file-enc",
        "date"    : now.strftime("%Y-%m-%d"),
        "time"    : now.strftime("%H:%M:%S"),
        "original": f"[FILE] {path}",
        "key"     : key,
        "cipher"  : cipher[:80] + "...",
        "result"  : "",
        "preview" : f"[FILE] {os.path.basename(path)}",
    }
    session_log.append(entry)
    save_history(entry)
    input(theme["info"]("\nTekan Enter..."))


# ─── FILE DECRYPT HANDLER ─────────────────────────────────────────────────────

def handle_file_decrypt(t, theme: dict, session_log: list):
    print(t.home + t.clear)
    key_path = input("\n[+] path file .key: ").strip()
    if not os.path.isfile(key_path):
        print(theme["error"]("[!] file key tidak ditemukan"))
        time.sleep(1.5)
        return

    enc_path = input("[+] path file .enc: ").strip()
    if not os.path.isfile(enc_path):
        print(theme["error"]("[!] file cipher tidak ditemukan"))
        time.sleep(1.5)
        return

    try:
        with open(key_path, "r") as fk:
            key = fk.read().strip()
        with open(enc_path, "r") as fc:
            cipher = fc.read().strip()
    except Exception as e:
        print(theme["error"](f"[!] gagal baca file: {e}"))
        time.sleep(1.5)
        return

    valid, msg = validate_key_format(key)
    if not valid:
        print(theme["error"](f"[!] {msg}"))
        time.sleep(1.5)
        return

    try:
        result = decrypt(cipher, key)
    except Exception as e:
        print(theme["error"](f"[!] decrypt gagal: {e}"))
        time.sleep(1.5)
        return

    out_path = enc_path.replace(".enc", ".dec")
    with open(out_path, "w", encoding="utf-8") as fo:
        fo.write(result)

    print(theme["primary"](f"\n[✓] disimpan di: {out_path}"))
    print(theme["accent"](f"preview: {result[:100]}{'...' if len(result) > 100 else ''}"))

    now = datetime.now()
    entry = {
        "type"    : "file-dec",
        "date"    : now.strftime("%Y-%m-%d"),
        "time"    : now.strftime("%H:%M:%S"),
        "original": "",
        "key"     : key,
        "cipher"  : cipher[:80] + "...",
        "result"  : result[:100],
        "preview" : f"[FILE-DEC] {os.path.basename(enc_path)}",
    }
    session_log.append(entry)
    save_history(entry)
    input(theme["info"]("\nTekan Enter..."))


# ─── MAIN TUI ─────────────────────────────────────────────────────────────────

MENU_ITEMS = [
    "encrypt",
    "decrypt",
    "encrypt file",
    "decrypt file",
    "history",
    "settings",
    "exit",
]


def draw_menu(t, theme: dict, idx: int, cfg: dict):
    w = t.width or 60
    print(t.home + t.clear)
    print(theme["primary"](format("Secret-2.0", font="small")))
    print(theme["sep"]("─" * w))
    print(theme["info"](f"  tema: {cfg.get('theme','green')}  ·  v2.0"))
    if DEBUG:
        show_debug_panel(theme)
    print(theme["sep"]("─" * w))
    print()
    for i, label in enumerate(MENU_ITEMS):
        if i == idx:
            print(theme["primary"](f"  ▶  {label.upper()}"))
        else:
            print(theme["accent"](f"     {label}"))
    print()
    print(theme["sep"]("─" * w))
    print(theme["info"]("  ↑↓ navigasi  ·  Enter pilih  ·  ESC keluar"))
    print(theme["sep"]("─" * w))
    print(theme["accent"](f"  <reiz_riz::UI>  <FU4Dxx28X::CORE>"))
    print(theme["sep"]("─" * w))


def main_tui():
    t   = terminal.Terminal()
    cfg = load_config()
    session_log: list = []
    idx = 0

    with t.hidden_cursor():
        print(t.home + t.clear)
        theme = get_theme(cfg)
        intro = "SECRET-2.0  ·  CIPHER TERMINAL"
        for c in intro:
            print(theme["primary"](c), end="", flush=True)
            time.sleep(0.028)
        print()
        time.sleep(0.35)

        while True:
            try:
                cfg   = load_config()
                theme = get_theme(cfg)
                draw_menu(t, theme, idx, cfg)

                with t.cbreak():
                    kp = t.inkey()

                if kp.name == "KEY_UP":
                    idx = (idx - 1) % len(MENU_ITEMS)
                    continue
                elif kp.name == "KEY_DOWN":
                    idx = (idx + 1) % len(MENU_ITEMS)
                    continue
                elif kp.name == "KEY_ESCAPE":
                    break
                elif kp.name != "KEY_ENTER":
                    continue

                selected = MENU_ITEMS[idx]

                if selected == "exit":
                    break
                elif selected == "encrypt":
                    scanline_clear(t, theme)
                    handle_encrypt(t, theme, session_log)
                elif selected == "decrypt":
                    scanline_clear(t, theme)
                    handle_decrypt(t, theme, session_log)
                elif selected == "encrypt file":
                    scanline_clear(t, theme)
                    handle_file_encrypt(t, theme, session_log)
                elif selected == "decrypt file":
                    scanline_clear(t, theme)
                    handle_file_decrypt(t, theme, session_log)
                elif selected == "history":
                    show_session_history(t, session_log, theme)
                elif selected == "settings":
                    cfg = show_settings(t, cfg)

            except KeyboardInterrupt:
                break
            except Exception as e:
                theme = get_theme(cfg)
                print(theme["error"](f"\n[!] error: {e}"))
                time.sleep(1.5)

    theme = get_theme(cfg)
    print(t.home + t.clear)
    for i in range(3, 0, -1):
        sys.stdout.write(theme["warn"](f"\r[!] session dihapus dalam {i}..."))
        sys.stdout.flush()
        time.sleep(1)
    session_log.clear()
    print(t.home + t.clear)
    print(theme["primary"]("[ session cleared — goodbye ]"))
    time.sleep(0.5)


# ─── CLI ONE-LINER MODE ───────────────────────────────────────────────────────

def main_cli():
    parser = argparse.ArgumentParser(
        prog="chat.py",
        description="Secret-2.0 — CLI one-liner mode",
    )
    parser.add_argument("action", choices=["enc", "dec"],
                        help="enc: enkripsi teks | dec: dekripsi cipher")
    parser.add_argument("text",
                        help="pesan (untuk enc) atau cipher hex (untuk dec)")
    parser.add_argument("--key", default=None,
                        help="secret key ascii85 (wajib untuk dec)")
    args = parser.parse_args()

    if args.action == "enc":
        cipher, key = encrypt(args.text)
        print(f"CIPHER : {cipher}")
        print(f"KEY    : {key}")
        print(f"FP     : {key_fingerprint(key)}")

    elif args.action == "dec":
        if not args.key:
            print("ERROR: --key diperlukan untuk decrypt", file=sys.stderr)
            sys.exit(1)
        valid, msg = validate_key_format(args.key)
        if not valid:
            print(f"ERROR: {msg}", file=sys.stderr)
            sys.exit(1)
        try:
            result = decrypt(args.text, args.key)
            print(f"RESULT : {result}")
        except Exception as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)


# ─── ENTRY ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) > 1:
        main_cli()
    else:
        main_tui()

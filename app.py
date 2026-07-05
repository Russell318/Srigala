
import os
import sys
import time
import threading
import itertools
from datetime import datetime

from flask import Flask, request, render_template, redirect, url_for, send_file, flash

import crypto_utils as ck
import network_relay as net

# =============================================================================
# STATE APLIKASI (in-memory, per proses)
# =============================================================================

state_lock = threading.Lock()
app_state = {'started': False, 'role': None, 'username': None, 'connected': False,
             'server_host': None, 'server_port': None}

directory = {}        # username -> pubkey PEM (dari server relay, trust-on-first-use)
sent_log = []
received_log = []     # list of dict, lihat stage_incoming_file() untuk skema field-nya

crypto_ctx = {'private_key': None, 'public_key': None, 'own_pubkey_pem': None,
              'received_dir': None, 'keydir': None}

socket_lock = threading.Lock()
client_socket_holder = {'sock': None}

_id_counter = itertools.count(1)


def _next_id():
    return next(_id_counter)


def _find_entry(entry_id):
    with state_lock:
        for e in received_log:
            if e['id'] == entry_id:
                return e
    return None


# =============================================================================
# TAHAP 1 — Terima paket terenkripsi, JANGAN langsung didekripsi (interaktif)
# =============================================================================

def stage_incoming_file(sender, package):
    entry = {
        'id': _next_id(),
        'sender': sender,
        'filename': package.get('filename', '(tanpa nama)'),
        'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'status': 'pending',       # pending -> valid | invalid (setelah user klik dekripsi)
        'package': package,        # payload masih terenkripsi apa adanya
        'steps': [],
        'saved_path': None,
        'decrypted_at': None,
    }
    with state_lock:
        received_log.insert(0, entry)


# =============================================================================
# TAHAP 2 — Proses dekripsi & verifikasi interaktif (dipicu tombol di GUI)
# =============================================================================

def perform_decryption(entry):
    """Menjalankan ke-5 langkah kriptografi satu-per-satu dan mencatat hasil
    tiap langkah supaya bisa ditampilkan ke pengguna di halaman /decrypt."""
    package = entry['package']
    steps = []
    overall_ok = True
    aes_key = None
    plaintext = None

    # Langkah 1: ECDH + HKDF -> turunkan kunci sesi AES (Pilar: Kerahasiaan)
    try:
        ephemeral_pub = ck.public_key_from_pem(package['ephemeral_pubkey'])
        aes_key = ck.derive_aes_key(crypto_ctx['private_key'], ephemeral_pub)
        steps.append({
            'name': 'Penurunan kunci sesi (ECDH + HKDF-SHA256)',
            'pillar': 'Kerahasiaan',
            'ok': True,
            'detail': f'Kunci AES-256 berhasil diturunkan dari shared secret ECDH. '
                      f'Cuplikan kunci (hex): {aes_key.hex()[:16]}... — kunci ini TIDAK PERNAH dikirim lewat jaringan.'
        })
    except Exception as e:
        steps.append({'name': 'Penurunan kunci sesi (ECDH + HKDF-SHA256)', 'pillar': 'Kerahasiaan',
                       'ok': False, 'detail': f'Gagal: {e}'})
        overall_ok = False

    # Langkah 2: AES-256-GCM decrypt (Pilar: Kerahasiaan + Integritas via auth tag)
    if aes_key is not None:
        try:
            nonce = ck.b64d(package['nonce'])
            ciphertext = ck.b64d(package['ciphertext'])
            plaintext = ck.aes_decrypt(aes_key, nonce, ciphertext)
            steps.append({
                'name': 'Dekripsi AES-256-GCM',
                'pillar': 'Kerahasiaan + Integritas',
                'ok': True,
                'detail': f'Berhasil, {len(plaintext)} byte plaintext dipulihkan. Auth tag GCM valid '
                          f'(artinya ciphertext tidak diubah sedikit pun sejak dienkripsi).'
            })
        except Exception:
            steps.append({
                'name': 'Dekripsi AES-256-GCM', 'pillar': 'Kerahasiaan + Integritas', 'ok': False,
                'detail': 'GAGAL — auth tag GCM tidak valid. Ciphertext rusak/berubah di jalan, atau kunci salah.'
            })
            overall_ok = False
    else:
        steps.append({'name': 'Dekripsi AES-256-GCM', 'pillar': 'Kerahasiaan + Integritas', 'ok': False,
                       'detail': 'Dilewati karena kunci sesi gagal diturunkan.'})
        overall_ok = False

    # Langkah 3: cocokkan hash SHA-256 (Pilar: Integritas, lapis ke-2)
    if plaintext is not None:
        actual_hash = ck.sha256_hex(plaintext)
        expected_hash = package.get('file_hash', '')
        hash_ok = actual_hash == expected_hash
        steps.append({
            'name': 'Pencocokan hash SHA-256', 'pillar': 'Integritas', 'ok': hash_ok,
            'detail': f'Hash dihitung ulang dari plaintext: {actual_hash[:20]}... '
                      f'{"COCOK" if hash_ok else "TIDAK COCOK"} dengan hash yang diklaim pengirim.'
        })
        if not hash_ok:
            overall_ok = False
    else:
        hash_ok = False
        steps.append({'name': 'Pencocokan hash SHA-256', 'pillar': 'Integritas', 'ok': False,
                       'detail': 'Dilewati karena dekripsi gagal.'})
        overall_ok = False

    # Langkah 4: verifikasi tanda tangan ECDSA (Pilar: Autentikasi)
    sig_ok = False
    try:
        sender_pub = ck.public_key_from_pem(package['sender_pubkey'])
        sig_ok = ck.verify_signature(sender_pub, package['file_hash'].encode('utf-8'),
                                      ck.b64d(package['signature']))
        steps.append({
            'name': 'Verifikasi tanda tangan ECDSA', 'pillar': 'Autentikasi', 'ok': sig_ok,
            'detail': ('Tanda tangan valid — hash file memang ditandatangani oleh pemegang kunci privat '
                       'yang berpasangan dengan kunci publik pengirim.') if sig_ok else
                      'Tanda tangan TIDAK valid — file bisa jadi dipalsukan / bukan dari pengirim asli.'
        })
    except Exception as e:
        steps.append({'name': 'Verifikasi tanda tangan ECDSA', 'pillar': 'Autentikasi', 'ok': False,
                       'detail': f'Error: {e}'})
    if not sig_ok:
        overall_ok = False

    # Langkah 5: cocokkan kunci publik pengirim dengan direktori server (Pilar: Non-Repudiasi)
    with state_lock:
        trusted_pub = directory.get(entry['sender'])
    identity_ok = trusted_pub is not None and trusted_pub == package.get('sender_pubkey')
    steps.append({
        'name': 'Pencocokan identitas ke direktori server relay', 'pillar': 'Non-Repudiasi', 'ok': identity_ok,
        'detail': ('Kunci publik pengirim cocok dengan catatan direktori server — pengirim tidak bisa '
                   'menyangkal telah mengirim file ini.') if identity_ok else
                  'Kunci publik TIDAK cocok dengan direktori server — indikasi spoofing / peniruan identitas.'
    })
    if not identity_ok:
        overall_ok = False

    saved_path = None
    if overall_ok and plaintext is not None:
        safe_name = os.path.basename(entry['filename'])
        timestamp = int(time.time() * 1000)
        saved_path = os.path.join(crypto_ctx['received_dir'], f'{timestamp}_{safe_name}')
        with open(saved_path, 'wb') as f:
            f.write(plaintext)

    with state_lock:
        entry['steps'] = steps
        entry['status'] = 'valid' if overall_ok else 'invalid'
        entry['saved_path'] = saved_path
        entry['decrypted_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')


# =============================================================================
# Listener thread sisi CLIENT: terhubung ke server relay, terima pesan
# =============================================================================

def listener_thread(server_host, server_port):
    while True:
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((server_host, server_port))
            sock.settimeout(None)
            with socket_lock:
                client_socket_holder['sock'] = sock

            net.send_msg(sock, {'type': 'register', 'username': app_state['username'],
                                 'pubkey': crypto_ctx['own_pubkey_pem']})
            with state_lock:
                app_state['connected'] = True
            print(f"[CLIENT-{app_state['username']}] Terhubung ke {server_host}:{server_port}")

            while True:
                msg = net.recv_msg(sock)
                if msg is None:
                    break
                mtype = msg.get('type')
                if mtype == 'directory_response':
                    with state_lock:
                        directory.clear()
                        directory.update(msg.get('directory', {}))
                elif mtype == 'file_relay':
                    # Hanya "menampung" paket terenkripsi. TIDAK didekripsi otomatis.
                    stage_incoming_file(msg['sender'], msg['package'])
                elif mtype == 'error':
                    print(f"[CLIENT] Error dari server: {msg.get('message')}")

        except Exception as e:
            print(f"[CLIENT] Koneksi terputus/gagal ({e}), mencoba lagi dalam 3 detik...")

        with state_lock:
            app_state['connected'] = False
        with socket_lock:
            client_socket_holder['sock'] = None
        time.sleep(3)


def request_directory_refresh():
    with socket_lock:
        sock = client_socket_holder['sock']
    if sock:
        try:
            net.send_msg(sock, {'type': 'directory_request'})
            time.sleep(0.3)
        except Exception:
            pass


def encrypt_and_send(target, filename, filebytes):
    with state_lock:
        target_pub_pem = directory.get(target)
    if not target_pub_pem:
        return False, f"Kunci publik untuk '{target}' belum tersedia. Pastikan '{target}' sedang online."

    target_pub = ck.public_key_from_pem(target_pub_pem)
    ephemeral_priv, ephemeral_pub = ck.generate_keypair()          # kunci sekali-pakai per transfer
    aes_key = ck.derive_aes_key(ephemeral_priv, target_pub)
    nonce, ciphertext = ck.aes_encrypt(aes_key, filebytes)
    file_hash = ck.sha256_hex(filebytes)
    signature = ck.sign_data(crypto_ctx['private_key'], file_hash.encode('utf-8'))

    package = {
        'filename': filename, 'sender': app_state['username'],
        'ephemeral_pubkey': ck.public_key_to_pem(ephemeral_pub),
        'nonce': ck.b64e(nonce), 'ciphertext': ck.b64e(ciphertext),
        'file_hash': file_hash, 'signature': ck.b64e(signature),
        'sender_pubkey': crypto_ctx['own_pubkey_pem'],
    }

    with socket_lock:
        sock = client_socket_holder['sock']
    if not sock:
        return False, "Tidak terhubung ke server."

    try:
        net.send_msg(sock, {'type': 'file', 'target': target, 'package': package})
    except Exception as e:
        return False, f"Gagal mengirim: {e}"

    with state_lock:
        sent_log.insert(0, {
            'target': target, 'filename': filename,
            'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'file_hash': file_hash, 'size': len(filebytes),
        })
    return True, "File berhasil dienkripsi & dikirim (masih terenkripsi sampai penerima menekan tombol dekripsi)."


# =============================================================================
# FLASK GUI
# =============================================================================

app = Flask(__name__)
app.secret_key = os.urandom(16)
APP_TITLE = "SRIGALA"


def _common_ctx():
    """Konteks dasar yang dipakai berulang di semua halaman setelah 'Mulai'
    (status koneksi, peer online, dsb) supaya tidak ditulis berkali-kali."""
    with state_lock:
        ctx = dict(
            app_title=APP_TITLE,
            username=app_state['username'],
            role=app_state['role'],
            connected=app_state['connected'],
            server_host=app_state['server_host'],
            server_port=app_state['server_port'],
            directory=dict(directory),
            own_pubkey=crypto_ctx['own_pubkey_pem'],
            own_fingerprint=ck.fingerprint(crypto_ctx['own_pubkey_pem']) if crypto_ctx['own_pubkey_pem'] else '',
            own_ip=net.get_local_ip(),
            pending_count=len([r for r in received_log if r['status'] == 'pending']),
        )
    return ctx


@app.route('/', methods=['GET'])
def index():
    with state_lock:
        started = app_state['started']
    if not started:
        return render_template('setup.html', app_title=APP_TITLE)

    ctx = _common_ctx()
    with state_lock:
        ctx['received_log'] = list(received_log)
        ctx['sent_log'] = list(sent_log)
    return render_template('dashboard.html', **ctx)


@app.route('/start', methods=['POST'])
def start():
    with state_lock:
        if app_state['started']:
            return redirect(url_for('index'))

    role = request.form.get('role', 'client')
    username = request.form.get('username', '').strip()
    if not username:
        flash('Username wajib diisi.', 'err')
        return redirect(url_for('index'))

    try:
        if role == 'host':
            relay_port = int(request.form.get('relay_port', 9100))
            server_ip = '127.0.0.1'
            server_port = relay_port
        else:
            server_ip = request.form.get('server_ip', '127.0.0.1').strip() or '127.0.0.1'
            server_port = int(request.form.get('server_port', 9100))
    except ValueError:
        flash('Port harus berupa angka.', 'err')
        return redirect(url_for('index'))

    base_dir = os.path.join('data', username)
    received_dir = os.path.join(base_dir, 'received')
    keydir = os.path.join(base_dir, 'keys')
    os.makedirs(received_dir, exist_ok=True)

    private_key, public_key = ck.get_or_create_keypair(username, keydir=keydir)
    crypto_ctx['private_key'] = private_key
    crypto_ctx['public_key'] = public_key
    crypto_ctx['own_pubkey_pem'] = ck.public_key_to_pem(public_key)
    crypto_ctx['received_dir'] = received_dir
    crypto_ctx['keydir'] = keydir

    if role == 'host':
        ok, message = net.start_relay_server(server_port)
        if not ok:
            flash(f'Gagal menjalankan server relay di port {server_port}: {message}', 'err')
            return redirect(url_for('index'))

    with state_lock:
        app_state['started'] = True
        app_state['role'] = role
        app_state['username'] = username
        app_state['server_host'] = server_ip
        app_state['server_port'] = server_port

    threading.Thread(target=listener_thread, args=(server_ip, server_port), daemon=True).start()
    time.sleep(0.5)
    request_directory_refresh()

    return redirect(url_for('index'))


@app.route('/refresh', methods=['POST'])
def refresh():
    request_directory_refresh()
    flash('Direktori kunci publik diperbarui.', 'ok')
    return redirect(url_for('index'))


@app.route('/send', methods=['GET', 'POST'])
def send_file_route():
    with state_lock:
        started = app_state['started']
    if not started:
        return redirect(url_for('index'))

    if request.method == 'POST':
        target = request.form.get('target')
        file = request.files.get('file')
        if not target or not file or file.filename == '':
            flash('Pilih target dan file terlebih dahulu.', 'err')
            return redirect(url_for('send_file_route'))

        filebytes = file.read()
        ok, message = encrypt_and_send(target, file.filename, filebytes)
        flash(message, 'ok' if ok else 'err')
        return redirect(url_for('send_file_route'))

    ctx = _common_ctx()
    with state_lock:
        ctx['sent_log'] = list(sent_log)
    return render_template('send.html', **ctx)


@app.route('/inbox', methods=['GET'])
def inbox_view():
    with state_lock:
        started = app_state['started']
    if not started:
        return redirect(url_for('index'))

    ctx = _common_ctx()
    with state_lock:
        ctx['received_log'] = list(received_log)
    return render_template('inbox.html', **ctx)


@app.route('/decrypt/<int:entry_id>', methods=['GET', 'POST'])
def decrypt_view(entry_id):
    entry = _find_entry(entry_id)
    if entry is None:
        flash('File tidak ditemukan.', 'err')
        return redirect(url_for('index'))

    if request.method == 'POST':
        perform_decryption(entry)
        return redirect(url_for('decrypt_view', entry_id=entry_id))

    package = entry['package']
    ctx = _common_ctx()
    ctx['entry'] = entry
    ctx['package'] = package
    return render_template('decrypt.html', **ctx)


@app.route('/download/<int:entry_id>')
def download(entry_id):
    entry = _find_entry(entry_id)
    if entry is None:
        return "File tidak ditemukan", 404
    if entry['status'] != 'valid' or not entry['saved_path']:
        return "File ini belum/tidak lolos verifikasi dan tidak dapat diunduh.", 403
    return send_file(entry['saved_path'], as_attachment=True, download_name=entry['filename'])


@app.route('/keys', methods=['GET'])
def keys_view():
    with state_lock:
        started = app_state['started']
    if not started:
        return redirect(url_for('index'))
    ctx = _common_ctx()
    return render_template('keys.html', **ctx)


@app.route('/keys/regenerate', methods=['POST'])
def keys_regenerate():
    with state_lock:
        started = app_state['started']
        username = app_state['username']
    if not started:
        return redirect(url_for('index'))

    private_key, public_key = ck.regenerate_keypair(username, crypto_ctx['keydir'])
    crypto_ctx['private_key'] = private_key
    crypto_ctx['public_key'] = public_key
    crypto_ctx['own_pubkey_pem'] = ck.public_key_to_pem(public_key)

    # kabari server relay bahwa kunci publik kita berubah
    with socket_lock:
        sock = client_socket_holder['sock']
    if sock:
        try:
            net.send_msg(sock, {'type': 'register', 'username': username, 'pubkey': crypto_ctx['own_pubkey_pem']})
        except Exception:
            pass

    flash('Kunci identitas baru dibuat. Peer lain perlu me-refresh direktori untuk melihat kunci baru Anda; '
          'file lama yang ditandatangani dengan kunci lama tidak akan lolos verifikasi.', 'ok')
    return redirect(url_for('keys_view'))


if __name__ == '__main__':
    flask_port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    print(f"SRIGALA siap. Buka http://127.0.0.1:{flask_port} lalu pilih peran HOST atau CLIENT.")
    app.run(host='0.0.0.0', port=flask_port, debug=False, use_reloader=False)

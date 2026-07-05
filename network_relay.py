"""
network_relay.py
=================
Bagian jaringan mentah (socket TCP): framing pesan JSON dan server relay.

Server relay (peran HOST) HANYA meneruskan paket yang sudah terenkripsi
end-to-end dan menjaga direktori kunci publik antar peer. Server ini
TIDAK PERNAH melihat isi file asli maupun kunci AES.
"""

import socket
import threading
import json


# -----------------------------------------------------------------------
# Framing pesan: 8 byte panjang (big-endian) + payload JSON
# -----------------------------------------------------------------------

def send_msg(sock, obj):
    data = json.dumps(obj).encode('utf-8')
    sock.sendall(len(data).to_bytes(8, 'big') + data)


def recv_exact(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def recv_msg(sock):
    header = recv_exact(sock, 8)
    if header is None:
        return None
    length = int.from_bytes(header, 'big')
    data = recv_exact(sock, length)
    if data is None:
        return None
    return json.loads(data.decode('utf-8'))


def get_local_ip():
    """Tebak IP lokal (untuk ditampilkan ke user sebagai alamat HOST)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip


# -----------------------------------------------------------------------
# Server relay (aktif hanya kalau peran = HOST)
# -----------------------------------------------------------------------

relay_clients = {}    # username -> socket
relay_pubkeys = {}    # username -> pem
relay_lock = threading.Lock()
relay_state = {'running': False, 'port': None}


def relay_broadcast_directory():
    with relay_lock:
        directory_snapshot = dict(relay_pubkeys)
        targets = list(relay_clients.values())
    msg = {'type': 'directory_response', 'directory': directory_snapshot}
    for sock in targets:
        try:
            send_msg(sock, msg)
        except Exception:
            pass


def relay_handle_client(client_socket, address):
    username = None
    try:
        msg = recv_msg(client_socket)
        if not msg or msg.get('type') != 'register':
            client_socket.close()
            return

        username = msg['username']
        pubkey_pem = msg['pubkey']

        with relay_lock:
            relay_clients[username] = client_socket
            relay_pubkeys[username] = pubkey_pem

        print(f"[RELAY] {username} terhubung dari {address}")
        relay_broadcast_directory()

        while True:
            msg = recv_msg(client_socket)
            if msg is None:
                break
            mtype = msg.get('type')

            if mtype == 'directory_request':
                with relay_lock:
                    directory_snapshot = dict(relay_pubkeys)
                send_msg(client_socket, {'type': 'directory_response', 'directory': directory_snapshot})

            elif mtype == 'file':
                target = msg.get('target')
                package = msg.get('package')
                with relay_lock:
                    target_socket = relay_clients.get(target)
                if target_socket:
                    try:
                        send_msg(target_socket, {'type': 'file_relay', 'sender': username, 'package': package})
                        print(f"[RELAY] File dari '{username}' diteruskan ke '{target}' (masih terenkripsi)")
                    except Exception:
                        print(f"[RELAY] Gagal meneruskan file ke '{target}'")
                else:
                    send_msg(client_socket, {'type': 'error', 'message': f"User '{target}' tidak online."})

            elif mtype == 'quit':
                break

    except (ConnectionResetError, ConnectionAbortedError):
        pass
    except Exception as e:
        print(f"[RELAY] Error saat menangani client: {e}")
    finally:
        with relay_lock:
            if username and relay_clients.get(username) is client_socket:
                del relay_clients[username]
                relay_pubkeys.pop(username, None)
        if username:
            print(f"[RELAY] {username} terputus.")
            relay_broadcast_directory()
        client_socket.close()


def start_relay_server(listen_port: int):
    """Menjalankan server relay di background thread. Mengembalikan (ok, pesan)."""
    if relay_state['running']:
        return True, 'Server relay sudah berjalan.'

    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('0.0.0.0', listen_port))
        server_socket.listen()
    except Exception as e:
        return False, str(e)

    def accept_loop():
        print(f"[RELAY] Server relay berjalan di 0.0.0.0:{listen_port}")
        while True:
            try:
                client_socket, address = server_socket.accept()
            except OSError:
                break
            threading.Thread(target=relay_handle_client, args=(client_socket, address), daemon=True).start()

    threading.Thread(target=accept_loop, daemon=True).start()
    relay_state['running'] = True
    relay_state['port'] = listen_port
    return True, 'OK'

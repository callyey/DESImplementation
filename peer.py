import argparse, socket, struct, threading, sys
import des

SHARED_KEY = b"KeyKI-267"   

def send_frame(sock, data: bytes):
    sock.sendall(struct.pack(">I", len(data)) + data)   

def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Koneksi terputus")
        buf += chunk
    return buf

def recv_frame(sock):
    (length,) = struct.unpack(">I", recv_exact(sock, 4))
    return recv_exact(sock, length)

def receiver_loop(sock, name):
    try:
        while True:
            ct = recv_frame(sock)
            print(f"\n[{name}] <- Ciphertext diterima (hex): {ct.hex()}")
            try:
                pt = des.decrypt(ct, SHARED_KEY).decode()
                print(f"[{name}] <- Plaintext hasil dekripsi : {pt}")
            except Exception as e:
                print(f"[{name}] !! Gagal dekripsi: {e}")
            print("> ", end="", flush=True)
    except (ConnectionError, OSError):
        print("\n[Info] Lawan bicara terputus. Tekan Enter untuk keluar.")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["server", "client"])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5000)
    a = ap.parse_args()

    if a.mode == "server":
        srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", a.port)); srv.listen(1)
        print(f"[Server] Menunggu koneksi di port {a.port} ...")
        sock, addr = srv.accept()
        print(f"[Server] Terhubung dengan {addr}")
        name = "Server"
    else:
        sock = socket.socket(); sock.connect((a.host, a.port))
        print(f"[Client] Terhubung ke {a.host}:{a.port}")
        name = "Client"

    threading.Thread(target=receiver_loop, args=(sock, name), daemon=True).start()
    print("Ketik pesan lalu Enter (ketik 'exit' untuk keluar)")
    try:
        while True:
            msg = input("> ")
            if msg.strip().lower() == "exit":
                break
            ct = des.encrypt(msg.encode(), SHARED_KEY)
            print(f"[{name}] -> Plaintext      : {msg}")
            print(f"[{name}] -> Ciphertext hex : {ct.hex()}")
            send_frame(sock, ct)
    except (EOFError, KeyboardInterrupt, OSError):
        pass
    sock.close()

if __name__ == "__main__":
    main()

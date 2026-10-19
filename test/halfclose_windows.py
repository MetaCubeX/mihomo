"""Compare stock/patched cores using isolated loopback-only HTTP CONNECT sessions.

No user config, controller credentials, system proxy or active core is modified.
Run with --stock EXE --patched EXE --output JSON. Windows only.
"""

import argparse
import collections
import concurrent.futures
import ctypes
import json
import os
import pathlib
import socket
import struct
import subprocess
import tempfile
import threading
import time


def tcp_states(pid):
    api = ctypes.WinDLL("iphlpapi").GetExtendedTcpTable
    api.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32), ctypes.c_bool,
                    ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32]
    api.restype = ctypes.c_uint32
    size = ctypes.c_uint32()
    api(None, ctypes.byref(size), False, socket.AF_INET, 5, 0)
    data = ctypes.create_string_buffer(size.value)
    error = api(data, ctypes.byref(size), False, socket.AF_INET, 5, 0)
    if error:
        raise OSError(error, "GetExtendedTcpTable")
    states = collections.Counter()
    for index in range(struct.unpack_from("<I", data)[0]):
        row = struct.unpack_from("<6I", data, 4 + index * 24)
        if row[5] == pid:
            states[row[0]] += 1
    return {"fin_wait_2": states[7], "close_wait": states[8],
            "established": states[5], "listen": states[2]}


def process_handles(pid):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_bool, ctypes.c_uint32]
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.GetProcessHandleCount.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    process = kernel.OpenProcess(0x1000, False, pid)
    if not process:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        count = ctypes.c_uint32()
        if not kernel.GetProcessHandleCount(process, ctypes.byref(count)):
            raise ctypes.WinError(ctypes.get_last_error())
        return count.value
    finally:
        kernel.CloseHandle(process)


def choose_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def run_case(label, binary, count, wait_seconds):
    clients = []
    peers = []
    workers = []
    process = None
    stop = threading.Event()
    with tempfile.TemporaryDirectory(prefix="mihomo-halfclose-") as directory:
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(count)
        listener.settimeout(1)
        backend_port = listener.getsockname()[1]

        def serve_peer(peer):
            peers.append(peer)
            try:
                peer.settimeout(1)
                peer.sendall(b"half-close-response")
                peer.shutdown(socket.SHUT_WR)
                while not stop.is_set():
                    try:
                        if not peer.recv(4096):
                            break
                    except socket.timeout:
                        continue
            except OSError:
                pass
            finally:
                peer.close()

        def accept_peers():
            while not stop.is_set():
                try:
                    peer, _ = listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                thread = threading.Thread(target=serve_peer, args=(peer,), daemon=True)
                workers.append(thread)
                thread.start()

        acceptor = threading.Thread(target=accept_peers, daemon=True)
        acceptor.start()
        proxy_port = choose_port()
        config = pathlib.Path(directory, "config.yaml")
        config.write_text(f"mixed-port: {proxy_port}\nallow-lan: false\n"
                          "bind-address: 127.0.0.1\nmode: rule\nlog-level: silent\n"
                          "dns:\n  enable: false\nproxies: []\nrules:\n  - MATCH,DIRECT\n",
                          encoding="utf-8")
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith("CLASH_") and key not in ("SAFE_PATHS", "SKIP_SAFE_PATH_CHECK")}
        try:
            with open(pathlib.Path(directory, "core.log"), "wb") as log:
                process = subprocess.Popen([binary, "-d", directory, "-f", str(config)],
                                           cwd=directory, env=environment,
                                           stdout=log, stderr=log,
                                           creationflags=subprocess.CREATE_NO_WINDOW)
                for _ in range(100):
                    if process.poll() is not None:
                        raise RuntimeError(f"{label} core exited: {process.returncode}")
                    try:
                        with socket.create_connection(("127.0.0.1", proxy_port), timeout=.2):
                            break
                    except OSError:
                        time.sleep(.1)
                else:
                    raise RuntimeError(f"{label} core did not start")
                for _ in range(count):
                    client = socket.create_connection(("127.0.0.1", proxy_port), timeout=10)
                    clients.append(client)
                    target = f"127.0.0.1:{backend_port}"
                    client.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
                    header = b""
                    while not header.endswith(b"\r\n\r\n"):
                        part = client.recv(1)
                        if not part:
                            raise RuntimeError(f"{label}: EOF before CONNECT response")
                        header += part
                    if b" 200 " not in header:
                        raise RuntimeError(f"{label}: CONNECT failed")
                    response = b""
                    while part := client.recv(4096):
                        response += part
                    if response != b"half-close-response":
                        raise RuntimeError(f"{label}: response was truncated")
                    # Intentionally keep our sending direction open after EOF.
                before = tcp_states(process.pid)
                handles_before = process_handles(process.pid)
                started = time.monotonic()
                time.sleep(wait_seconds)
                after = tcp_states(process.pid)
                return {"case": label, "sessions": count, "wait_seconds": round(time.monotonic()-started, 2),
                        "handles_before": handles_before, "handles_after": process_handles(process.pid),
                        "before": before, "after": after}
        finally:
            stop.set()
            for client in clients:
                client.close()
            listener.close()
            for peer in peers:
                peer.close()
            acceptor.join(2)
            for worker in workers:
                worker.join(2)
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(5)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--stock", required=True)
    parser.add_argument("--patched", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--connections", type=int, default=24)
    parser.add_argument("--wait", type=float, default=35)
    args = parser.parse_args()
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(run_case, label, str(pathlib.Path(binary).resolve()), args.connections, args.wait)
                   for label, binary in (("stock", args.stock), ("patched", args.patched))]
        results = [future.result() for future in futures]
    stock, patched = results
    success = (stock["before"]["fin_wait_2"] >= args.connections
               and stock["after"]["fin_wait_2"] >= args.connections
               and patched["before"]["fin_wait_2"] >= args.connections
               and patched["after"]["established"] == 0
               and patched["after"]["close_wait"] == 0
               and patched["handles_before"] - patched["handles_after"] >= args.connections
               and stock["handles_before"] - stock["handles_after"] < args.connections)
    report = {"passed": success,
              "note": "Windows may retain orphaned FIN_WAIT_2 endpoints after application Close; "
                      "handle release and outbound cleanup distinguish resource release from TCP state expiry.",
              "results": results}
    pathlib.Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if success else 1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3

# sys, signal
import socket, threading, json, base64
from pathlib import Path
from datetime import datetime

clients = {}
clientsLock = threading.RLock()

def sendMsg(conn, msg):
    msgJson = json.dumps(msg).encode('utf-8')
    length = len(msgJson).to_bytes(4, 'big')
    conn.sendall(length + msgJson)

def recvMsg(conn):
    try:
        lengthBytes = conn.recv(4)
        if not lengthBytes or len(lengthBytes) < 4:
            return None

        msgLen = int.from_bytes(lengthBytes, 'big')
        if msgLen > 1024 * 1024:
            return None

        chunks = []
        bytesRecv = 0
        while bytesRecv < msgLen:
            chunk = conn.recv(min(msgLen - bytesRecv, 4096))
            if not chunk:
                return None
            chunks.append(chunk)
            bytesRecv += len(chunk)

        return json.loads(b''.join(chunks).decode('utf-8'))
    except:
        return None

def xorCipher(data, key):
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data))

def encodeXor(msg, key):
    return base64.b64encode(xorCipher(msg, key).encode('latin1')).decode()

def broadcast(msg, exclude=None):
    with clientsLock:
        for username, client in list(clients.items()):
            if username != exclude and client['connected']:
                try:
                    sendMsg(client['conn'], msg)
                except:
                    client['connected'] = False

def handleClient(conn, addr, serverPass, showMessages, xorKey):
    username = None
    try:
        authMsg = recvMsg(conn)
        if not authMsg or authMsg.get('type') != 'auth':
            sendMsg(conn, {'type': 'error', 'message': 'auth required'})
            conn.close()
            return

        username = authMsg.get('username', '').strip()
        password = authMsg.get('password', '')

        if not username or len(username) > 32:
            sendMsg(conn, {'type': 'error', 'message': 'invalid username'})
            conn.close()
            return

        if password != serverPass:
            sendMsg(conn, {'type': 'error', 'message': 'wrong password'})
            print(f"[Warn] wrong password from {addr}")
            conn.close()
            return

        with clientsLock:
            if username in clients:
                sendMsg(conn, {'type': 'error', 'message': 'username taken'})
                conn.close()
                return

            clients[username] = {
                'conn': conn,
                'addr': addr,
                'connected': True
            }

        sendMsg(conn, {
            'type': 'auth_success',
            'message': f'welcome {username}!',
            'users': list(clients.keys())
        })

        if showMessages:
            print(f"[V] {username} connected from {addr}")

        broadcast({
            'type': 'user_join',
            'username': username,
            'timestamp': datetime.now().isoformat()
        }, exclude=username)

        while True:
            msg = recvMsg(conn)
            if msg is None:
                break

            msgType = msg.get('type')

            if msgType == 'chat':
                broadcast({
                    'type': 'chat',
                    'username': username,
                    'message': msg.get('message', ''),
                    'timestamp': datetime.now().isoformat()
                })
                if showMessages:
                    content = msg.get('message', '')
                    if xorKey:
                        print(f"[{username}] {encodeXor(content, xorKey)}")
                    else:
                        print(f"[{username}] {content}")

            elif msgType == 'typing':
                broadcast({
                    'type': 'typing',
                    'username': username
                }, exclude=username)

            elif msgType == 'disconnect':
                print(f"[exit] {username} disconnected")
                break

    except Exception as e:
        print(f"[err] err {username}: {e}")

    finally:
        if username:
            with clientsLock:
                if username in clients:
                    del clients[username]

            broadcast({
                'type': 'user_leave',
                'username': username,
                'timestamp': datetime.now().isoformat()
            })

        try:
            conn.close()
        except:
            pass

def setupHiddenService():
    hsDir = Path('/var/lib/tor/torchat')
    if not hsDir.exists():
        hsDir = Path.home() / '.torchat' / 'hidden_service'
        hsDir.mkdir(parents=True, exist_ok=True)

    hostnameFile = hsDir / 'hostname'
    if hostnameFile.exists():
        onion = hostnameFile.read_text().strip()
        print(f"[HX] service: {onion}")
        return onion
    else:
        print("[Adverment] This srver no detected Tor!")
        return None

def startServer(port, password, showMessages, xorKey):
    #onion = setupHiddenService()

    serverSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serverSock.bind(('127.0.0.1', port))
    serverSock.listen(10)

    print("[started server]")

    try:
        while True:
            conn, addr = serverSock.accept()
            print(f"[x!x] connection from {addr}")

            clientThread = threading.Thread(
                target=handleClient,
                args=(conn, addr, password, args.show, args.xor),
                daemon=True
            )
            clientThread.start()

    except KeyboardInterrupt:
        print("\n[Stoped!....]")
    finally:
        serverSock.close()

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='This is server')
    parser.add_argument('-p', '--port', type=int, default=8888)
    parser.add_argument('-P', '--password', required=True)
    parser.add_argument('-s', '--show', action='store_true', help='show messages')
    parser.add_argument('-x', '--xor', type=str, default=None, help='xor encrypt messages')

    args = parser.parse_args()

    startServer(args.port, args.password, args.show, args.xor)

#!/usr/bin/env python3

import socket, socks, time, threading, json, sys, os, re
from datetime import datetime

class Sex:
    END = "\033[0m"
    WHITE = "\033[1;97m"
    CYAN = "\033[38;5;37m"
    B_RED = "\033[38;5;196m"
    N_CYAN = "\033[38;5;51m"
    N_RED = "\033[38;5;9m"
    GRAY = "\033[38;5;244m"
    BLUE = "\033[1;34m"
    PURPLE = "\033[38;5;141m"

class TorChatClient:
    def __init__(self, onion, port, username, password, proxyHost='127.0.0.1', proxyPort=9050):
        self.onion = onion
        self.port = port
        self.username = username
        self.password = password
        self.proxyHost = proxyHost
        self.proxyPort = proxyPort
        self.sock = None
        self.connected = False
        self.running = False
        self.users = set()
        self.knownUsers = set()


        self.mutedUsers = set()
        self.startTime = time.time()

        self.blockedUsers = set()
        self.verifiedUsers = set()
        self.locked = False
        self.showColors = True
        self.messageHistory = []
        self.seenMessages = set()


    def sendMsg(self, msg):
        msgJson = json.dumps(msg).encode('utf-8')
        length = len(msgJson).to_bytes(4, 'big')
        self.sock.sendall(length + msgJson)

    def recvMsg(self):
        try:
            lengthBytes = self.sock.recv(4)
            if not lengthBytes or len(lengthBytes) < 4:
                return None

            msgLen = int.from_bytes(lengthBytes, 'big')
            if msgLen > 1024 * 1024:
                return None

            chunks = []
            bytesRecv = 0
            while bytesRecv < msgLen:
                chunk = self.sock.recv(min(msgLen - bytesRecv, 4096))
                if not chunk:
                    return None
                chunks.append(chunk)
                bytesRecv += len(chunk)

            return json.loads(b''.join(chunks).decode('utf-8'))
        except:
            return None

    def connect(self):
        try:
            print(f"{Sex.GRAY}[::]{Sex.END} {Sex.CYAN}Connecting...{Sex.END}")

            self.sock = socks.socksocket()
            self.sock.set_proxy(
                proxy_type=socks.SOCKS5,
                addr=self.proxyHost,
                port=self.proxyPort
            )
            self.sock.settimeout(None)

            print(f"{Sex.GRAY}[::]{Sex.END} {Sex.CYAN}Connecting to{Sex.END} {Sex.B_RED}{self.onion}:{self.port}...{Sex.END}")
            self.sock.connect((self.onion, self.port))

            print(f"{Sex.GRAY}Ok :: connected!{Sex.END}")

            if not self.authenticate():
                return False

            self.connected = True
            print(f"{Sex.GRAY}Auth as ::{Sex.END} {Sex.PURPLE}{self.username}{Sex.END}")
            return True

        except Exception as e:
            print(f"{Sex.B_RED}[err] connection error :: {e}{Sex.END}")
            return False

    def authenticate(self):
        try:
            authMsg = {
                'type': 'auth',
                'username': self.username,
                'password': self.password
            }
            self.sendMsg(authMsg)

            response = self.recvMsg()
            if not response:
                return False

            if response.get('type') == 'auth_success':
                self.users = set(response.get('users', []))
                return True
            else:
                print(f"{Sex.B_RED}error: {response.get('message', 'unknown')}{Sex.END}")
                return False
        except:
            return False

    def recvLoop(self):
        while self.running:
            try:
                msg = self.recvMsg()
                if msg is None:
                    if self.running:
                        print(f"\n{Sex.B_RED}[::] connection lost..{Sex.END}")
                        self.running = False
                    break

                self.processMsg(msg)
            except:
                if self.running:
                    break

    def processMsg(self, msg):
        msgType = msg.get('type')

        if msgType == 'chat':
            username = msg.get('username')
            if username in self.blockedUsers:
                return
            message = msg.get('message')
            timestamp = msg.get('timestamp', '')

            try:
                dt = datetime.fromisoformat(timestamp)
                timeStr = dt.strftime('%H:%M:%S')
            except:
                timeStr = ''

            print(f"{Sex.WHITE}{Sex.GRAY}[{timeStr}]{Sex.END} {Sex.PURPLE}{username}{Sex.END}{Sex.GRAY} ::{Sex.END} {message}")

        elif msgType == 'user_join':
            username = msg.get('username')
            self.users.add(username)
            self.knownUsers.add(username)
            print(f"{Sex.GRAY}[V] :: {username} joined{Sex.END}")

        elif msgType == 'user_leave':
            username = msg.get('username')
            self.users.discard(username)
            print(f"{Sex.GRAY}[X] :: {username} left{Sex.END}")

        elif msgType == 'error':
            error = msg.get('message', 'unknown error')
            print(f"{Sex.B_RED}[err] {error}{Sex.END}")

    def sendChat(self, text):
        self.sendMsg({
            'type': 'chat',
            'message': text
        })

    def bannerVyx(self):
        print(f"\n{Sex.GRAY}Welcome to the room private :: {datetime.now().date()}{Sex.END}\n{Sex.CYAN}Version{Sex.END} {Sex.GRAY}::{Sex.END}  {Sex.PURPLE}0.95{Sex.END}\n")
        print(f"{Sex.GRAY}server   ::{Sex.END} {self.onion}:{self.port}{Sex.END}")
        print(f"{Sex.GRAY}online   ::{Sex.END} {', '.join(sorted(self.users)) or 'No participants'}{Sex.END}")
        print(f"{Sex.GRAY}user     ::{Sex.END} {Sex.PURPLE}{self.username}{Sex.END}")
        print(f"{Sex.GRAY}port     ::{Sex.END} {self.port}{Sex.END}")
        print(f"\n{Sex.GRAY}  [commands]{Sex.END}")
        print(f"  /who   {Sex.GRAY}::{Sex.END}  {Sex.CYAN}show all users online in room{Sex.END}")
        print(f"  /help  {Sex.GRAY}::{Sex.END}  {Sex.CYAN}show all commands availables{Sex.END}")
        print(f"  /quit  {Sex.GRAY}::{Sex.END}  {Sex.CYAN}leave the room{Sex.END}\n\n")

    def inputLoop(self):
        try:
            while self.running:
                try:
                    text = input(f"{Sex.PURPLE}> {Sex.END}")

                    if not text.strip():
                        continue

                    if text.startswith('/'):
                        self.processCmd(text)
                    else:
                        self.sendChat(text)

                except EOFError:
                    break
                except KeyboardInterrupt:
                    print("\n")
                    break
        finally:
            self.disconnect()

    def processCmd(self, cmd):
        cmd = cmd.lower().strip()

        if cmd == "/who":
            users = set(self.users)
            users.add(self.username)
            print(f"\n{Sex.GRAY}  [Users]{Sex.END}")
            for u in sorted(users):
                print(f" • {Sex.PURPLE}{u}{Sex.END}")
            print("")

        elif cmd == '/me':
            print(f"{Sex.GRAY}[err] usage ::{Sex.END} {Sex.CYAN}/me <action>{Sex.END}")
        elif cmd.startswith('/me '):
            action = cmd.split(maxsplit=1)[1].strip()

            if not action:
                print(f"{Sex.B_RED}[err]{Sex.END} usage :: /me <action>")
                return
            self.sendChat(f"   {Sex.N_RED}[{self.username}]{Sex.END} {Sex.PURPLE}{action}{Sex.CYAN}")

        elif cmd == "/block":
            print(f"{Sex.GRAY}[err] usage ::{Sex.END} {Sex.CYAN}/block <user>{Sex.END}")
        elif cmd.startswith('/block '):
            user = cmd.split(maxsplit=1)[1]
            self.blockedUsers.add(user)
            print(f"{Sex.B_RED}[bloqued] ::{Sex.END} {user}{Sex.END}")

        elif cmd == "/unblock":
            print(f"{Sex.GRAY}[err] usage ::{Sex.END} {Sex.CYAN}/unblock <user>{Sex.END}")
        elif cmd.startswith('/unblock '):
            user = cmd.split(maxsplit=1)[1]
            self.blockedUsers.discard(user)
            print(f"{Sex.GRAY}[unblock] ::{Sex.END} {user}{Sex.END}")

        elif cmd == '/known':
            if self.knownUsers:
                print(f"\n[known users] ({len(self.knownUsers)})")
                for u in sorted(self.knownUsers):
                    print(f"  {u}")
                print("")
            else:
                print(f"[no known users]{Sex.END}\n")

        elif cmd == "/stats":
            uptime = int(time.time() - self.startTime)
            active = len(self.users)
            print(f"""
{Sex.GRAY}[stats]{Sex.END}
{Sex.WHITE}uptime  ::{Sex.END} {Sex.PURPLE}{uptime}s{Sex.END}
{Sex.WHITE}online  ::{Sex.END} {Sex.PURPLE}{active}{Sex.END}
{Sex.WHITE}known   ::{Sex.END} {Sex.PURPLE}{len(self.knownUsers)}{Sex.END}
{Sex.WHITE}muted   ::{Sex.END} {Sex.PURPLE}{len(self.blockedUsers)}{Sex.END}
""")

        elif cmd == '/clear':
            self.cleanScreen()
            self.cleanMem()
            print(f"{Sex.GRAY}[Cleaned][Sex.END]\n")

        elif cmd == '/cleam':
            self.cleanScreen()
            self.cleanMem()

            self.seenMessages.clear()
            self.messageHistory.clear()

            if self.onion:
                self.users.add(f"{self.onion}:{self.port}")

            print(f"{Sex.GRAY}[full clean memory and logs excuted!]{Sex.END}\n")

        elif cmd == '/help':
            print(f"\n{Sex.GRAY}[commands]     [desc]{Sex.END}")
            print(f"  /known   {Sex.GRAY}::{Sex.END} {Sex.CYAN}show known users{Sex.END}")
            print(f"  /who     {Sex.GRAY}::{Sex.END} {Sex.CYAN}show all users online{Sex.END}")
            print(f"  /me      {Sex.GRAY}::{Sex.END} {Sex.CYAN}actions text user{Sex.END}")
            print(f"  /clear   {Sex.GRAY}::{Sex.END} {Sex.CYAN}clean screen and memory{Sex.END}")
            print(f"  /cleam   {Sex.GRAY}::{Sex.END} {Sex.CYAN}clean full logs and memory{Sex.END}")
            print(f"  /block   {Sex.GRAY}::{Sex.END} {Sex.CYAN}block and mute user{Sex.END}")
            print(f"  /unblock {Sex.GRAY}::{Sex.END} {Sex.CYAN}unblock and unmute user{Sex.END}")
            print(f"  /stats   {Sex.GRAY}::{Sex.END} {Sex.CYAN}stats room{Sex.END}")
            print(f"  /quit    {Sex.GRAY}::{Sex.END} {Sex.CYAN}exit room{Sex.END}\n")

        elif cmd == '/quit':
            print(f"{Sex.GRAY}[stopped...]{Sex.END}")
            self.running = False

        else:
            print(f"{Sex.B_RED}unknown comd{Sex.END} {Sex.GRAY}::{Sex.END} {Sex.PURPLE}{cmd}{Sex.END}")
            print(f"{Sex.GRAY}[Type /help for view cmds{Sex.END}\n")

    def cleanScreen(self):
        if sys.platform.startswith('win'):
            os.system('cls')
        else:
            os.system('clear')

    def cleanMem(self):
        self.messageHistory.clear()
        self.seenMessages.clear()

    def disconnect(self):
        print(f"{Sex.B_RED}[warn]disconnecting...{Sex.END}")
        self.running = False

        if self.connected:
            try:
                self.sendMsg({'type': 'disconnect'})
            except:
                pass

        if self.sock:
            try:
                self.sock.close()
            except:
                pass

        print(f"{Sex.GRAY}[!X!]disconnected{Sex.END}")

    def start(self):
        if not self.connect():
            return

        self.running = True

        recvThread = threading.Thread(target=self.recvLoop, daemon=True)
        recvThread.start()

        self.bannerVyx()
        self.inputLoop()

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='p2p chat client!')
    parser.add_argument('-o', '--onion', required=True)
    parser.add_argument('-p', '--port', type=int, default=8888)
    parser.add_argument('-u', '--username', required=True)
    parser.add_argument('-P', '--password', required=True)
    parser.add_argument('-t', '--tor-proxy', default='127.0.0.1:9050')

    args = parser.parse_args()

    proxyParts = args.tor_proxy.split(':')
    proxyHost = proxyParts[0]
    proxyPort = int(proxyParts[1]) if len(proxyParts) > 1 else 9050

    try:
        testSock = socket.socket()
        testSock.settimeout(2)
        testSock.connect((proxyHost, proxyPort))
        testSock.close()
    except:
        print(f"{Sex.GRAY}[!x!] tor not running at {proxyHost}:{proxyPort}{Sex.END}")
        sys.exit(1)

    client = TorChatClient(
        onion=args.onion,
        port=args.port,
        username=args.username,
        password=args.password,
        proxyHost=proxyHost,
        proxyPort=proxyPort
    )

    client.start()

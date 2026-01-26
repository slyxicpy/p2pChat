#!/usr/bin/env python3
import ctypes
from ctypes import c_char_p, c_int16, c_size_t, c_uint8, c_int, POINTER, Structure, byref


import socket, socks, threading, json, sys, time, hashlib, re, os, base64, miniupnpc, mimetypes
from typing import LiteralString
from pathlib import Path
from datetime import datetime
from collections import deque

from tools import geo
#from tools import sip


from server import xorCipher

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

BOOTSTRAP_NODES = []

def genSecKey(length=32):
    import secrets
    randomBytes = secrets.token_bytes(length)
    return randomBytes.hex()

def keyToBytes(hexKey):
    try:
        return bytes.fromhex(hexKey)
    except:
        return None

def showKey(key):
    print(f"""
{Sex.GRAY}[KEY GENERATED] ::{Sex.END} {Sex.B_RED}{datetime.now().date()}{Sex.END}
{Sex.PURPLE}[{key}]{Sex.END}
""")

def validateKey(hexKey):
    if not hexKey:
        return False

    keyBytes = keyToBytes(hexKey)
    if not keyBytes:
        return False

    if len(keyBytes) < 32:
        print(f"{Sex.B_RED}[ERR] key short{Sex.END}\n{Sex.CYAN}Minimum 32 bytes[64 characters]{Sex.END}")
        return False
    return True

try:
    cryptoLib = ctypes.CDLL('lib/libcrypto.so')
    protocolLib = ctypes.CDLL('lib/libprotocol.so')
    networkLib = ctypes.CDLL('lib/libnetwork.so')

    class CryptoHash(Structure):
        _fields_ = [
            ("hash", c_uint8 * 32),
            ("salt", c_uint8 * 32),
            ("iterations", ctypes.c_uint32)
        ]

    class CryptoMessage(Structure):
        _fields_ = [
            ("ciphertext", POINTER(c_uint8)),
            ("ciphertextLen", c_size_t),
            ("nonce", c_uint8 * 12),
            ("tag", c_uint8 * 16)
        ]

    cryptoLib.cryptoHashPassword.argtypes = [c_char_p, c_size_t, POINTER(c_uint8), POINTER(CryptoHash)]
    cryptoLib.cryptoHashPassword.restype = c_int

    cryptoLib.cryptoEncryptMessage.argtypes = [POINTER(c_uint8), c_size_t, POINTER(c_uint8), POINTER(CryptoMessage)]
    cryptoLib.cryptoEncryptMessage.restype = c_int

    cryptoLib.cryptoDecryptMessage.argtypes = [POINTER(CryptoMessage), POINTER(c_uint8), POINTER(POINTER(c_uint8)), POINTER(c_size_t)]
    cryptoLib.cryptoDecryptMessage.restype = c_int

    cryptoLib.cryptoFreeMessage.argtypes = [POINTER(CryptoMessage)]
    cryptoLib.cryptoFreeMessage.restype = None

    cryptoLib.cryptoRandomBytes.argtypes = [POINTER(c_uint8), c_size_t]
    cryptoLib.cryptoRandomBytes.restype = c_int

    cryptoLib.cryptoEncryptMessage.argtypes = [POINTER(c_uint8), c_size_t, POINTER(c_uint8), POINTER(CryptoMessage)]

    USE_C_LIBS = True
    print(f"{Sex.CYAN}[libs]{Sex.END} {Sex.PURPLE}[using modules]{Sex.END}")
except:
    USE_C_LIBS = False
    print(f"{Sex.B_RED}[WARNING]{Sex.END} {Sex.GRAY}[using python pure]{Sex.END}")

#MAX_PEERS = 666
#MESSAGE_HISTORY = 300
#GOSSIP_INTERVAL = 2
#HEARTBEAT_INTERVAL = 40



class P2PNode:
    def __init__(self, port, username, password=None, sharedKey=None, onion=None, proxyHost='127.0.0.1', proxyPort=9050):
        self.port = port
        self.username = username
        self.password = password # to sharedKey
        self.sharedKey = sharedKey
        if password and sharedKey:
            raise ValueError("cannot use both passowrd and key\n[choose one]")
        if not password and not sharedKey:
            raise ValueError("mus provide either password(-P) or key(-gk)")

        if password:
            self.authCredential = password.encode() if isinstance(password, str) else password
            self.credentialType = 'password'
        else:
            self.authCredential = sharedKey
            self.credentialType = 'key'

        # fingerprt
        self.verifyEnabled = False
        self.myFingerprint = None
        self.trustedFingerprints = {}

        self.myOnion = onion
        self.proxyHost = proxyHost
        self.proxyPort = proxyPort

        self.peers = {}
        self.peersLock = threading.Lock()
        self.knownPeers = set()
        self.knownPeersLock = threading.Lock()

        self.seenMessages = set()
        self.seenMessagesLock = threading.Lock()
        self.messageHistory = deque(maxlen=MESSAGE_HISTORY)

        self.running = False
        self.serverSock = None

        # cmds nw
        self.mutedUsers = set()
        self.startTime = time.time()

        self.blockedUsers = set()
        self.verifiedUsers = set()
        self.locked = False
        self.showColors = True

        # xor
        self.xorKey = None

        # stealth mode
        self.stealthMode = False

        # destruct msg timer
        self.paranMode = False
        self.paranDelay = 0
        self.selfDestructTimers = {}

        # obfuscate mode
        self.obfuscateMode = False
        self.obfuscateThread = None

        # rate limit
        self.rateLimitMax = 0
        self.messageRates = {}
        self.rateCleanupTime = time.time()

#timeout
        self.peerTimeout = 280

        #white list * blacklist
        self.whitelist = set()
        self.blacklist = set()

        #logs
        self.logFile = None
        self.logLock = threading.Lock()

        #quiet
        self.quietMode = False

        # forward upnp
        self.upnpEnabled = False
        self.upnpMapping = False

        # relay mode
        self.relayMode = False
        self.relayStats ={'messages': 0, 'bytes': 0, 'peers': set()}

        # media transfer
        self.mediaEnabled = False
        self.mediaTransfer = {}
        self.mediaLock = threading.Lock()
        self.pendingTransfers = {}
        self.mediaDownload = Path('p2pMedia')

        # drops media
        self.dropTransfers = {}
        self.dropTimers = {}

        #to
        self.privateKeys = {}
        self.privateKeysLock = threading.Lock()



    # myFingerprint
    def genFingerprint(self, fpSize=32):
        import hashlib

        validSizes = [16, 32, 40, 60, 128, 256]
        if fpSize not in validSizes:
            print(f"{Sex.B_RED}[err]{Sex.END}{Sex.GRAY}[invalid fingerprt size]{Sex.END} {Sex.B_RED}-v :: --verify{Sex.END}")
            print(f"{Sex.GRAY}[Sizes]{Sex.END}  ::  {Sex.PURPLE}[16, 32, 40, 60, 128, 256]{Sex.END}")
            sys.exit(1)

        data = self.authCredential + self.username.encode()
        fullHash = hashlib.sha256(data).hexdigest()

        while len(fullHash) < fpSize:
            fullHash = hashlib.sha256(fullHash.encode()).hexdigest() + fullHash

        fp = fullHash[:fpSize].upper()

        if fpSize <= 32:
            formatted = ' '.join(fp[i:i+4] for i in range(0, len(fp), 4))
        elif fpSize <= 40:
            formatted = ' '.join(fp[i:i+5] for i in range(0, len(fp), 5))
        elif fpSize == 60:
            line1 = ' '.join([fp[i:i+5] for i in range(0, 30, 5)])
            line2 = ' '.join([fp[i:i+5] for i in range(30, 60, 5)])
            formatted = f"{line1}\n{line2}"
        elif fpSize == 128:
            lines = []
            for row in range(4):
                start = row * 32
                end = start + 32
                line = ' '.join([fp[i:i+4] for i in range(start, end, 4)])
                lines.append(line)
            formatted = '\n'.join(lines)
        else:
            lines = []
            for row in range(8):
                start = row * 32
                end = start + 32
                line = ' '.join([fp[i:i+4] for i in range(start, end, 4)])
                lines.append(line)
            formatted = '\n'.join(lines)
        self.myFingerprint = formatted
        self.verifyEnabled = True
        print(f"""
{Sex.GRAY}[Fingerprint[{fpSize}]]{Sex.END}::{Sex.PURPLE}ENABLED{Sex.END}
{Sex.CYAN}{self.myFingerprint}{Sex.END}
              """)

    def writeLog(self, message):
        if not self.logFile:
            return
        try:
            with self.logLock:
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                with open(self.logFile, 'a', encoding='utf-8') as f:
                    f.write(f"[{timestamp}] {message}\n")
        except Exception as e:
            pass

    def stealthMsg(self, msg):
        if not self.stealthMode:
            return msg

        stealthMsg = msg.copy()
        if 'username' in stealthMsg:
            stealthMsg['username'] = 'anon'
        if 'timestamp'in stealthMsg:
            del stealthMsg['timestamp']
        if 'ttl' in stealthMsg:
            stealthMsg['ttl'] = 1

        return stealthMsg

    def selfDestruct(self, msgId):
        if msgId in self.selfDestructTimers:
            del self.selfDestructTimers[msgId]

        with self.seenMessagesLock:
            for i,  msg in enumerate(list(self.messageHistory)):
                if msg.get('id') == msgId:
                    self.messageHistory.remove(msg)
                    if not self.quietMode:
                        print(f"{Sex.GRAY}[DELETED]{Sex.END}")
                    self.writeLog(f"[DELETED] message auto deleted: {msgId}")
                    break

    def scheduleDestruct(self, msgId):
        if not self.paranMode or self.paranDelay <= 0:
            return
        #timer  = threading.Timer(self.paranDelay, self.selfDestruct, args=(msgId))
        timer = threading.Timer(self.paranDelay, self.selfDestruct, args=(msgId,))

        timer.daemon = True
        timer.start()
        self.selfDestructTimers[msgId] = timer

    def obfuscateLoop(self):
        import random
        while self.running and self.obfuscateMode:
            time.sleep(random.randint(10, 60))
            if not self.running or not self.obfuscateMode:
                break
            noiseLength = random.randint(20, 100)
            noise = base64.b64encode(os.urandom(noiseLength)).decode()[:noiseLength]
            timestamp = datetime.now().isoformat()
            msgId = self.msgId('noise', noise, timestamp)
            noiseMsg = {
                'type': 'chat',
                'id': msgId,
                'username': '_noise_',
                'message': noise,
                'timestamp': timestamp,
                'ttl': 1,
                'crypto': False,
                'noise': True
            }

            self.broadcast(noiseMsg)

    def startObfuscate(self):
        if self.obfuscateMode and not self.obfuscateThread:
            self.obfuscateThread = threading.Thread(target=self.obfuscateLoop, daemon=True)
            self.obfuscateThread.start()
            if not self.quietMode:
                print(f"{Sex.GRAY}[AV][Obuscate]{Sex.END}      :: {Sex.CYAN}ON{Sex.END}")

    def checkRateLimit(self, username):
        if self.rateLimitMax <= 0:
            return True

        now = time.time()

        if now - self.rateCleanupTime > 60:
            self.rateCleanupTime = now
            for user in list(self.messageRates.keys()):
                self.messageRates[user] = [t for t in self.messageRates[user] if now - t < 60]
                if not self.messageRates[user]:
                    del self.messageRates[user]

        if username not in self.messageRates:
            self.messageRates[username] = []

        self.messageRates[username] = [t for t in self.messageRates[username] if now - t < 60]

        if len(self.messageRates[username]) >= self.rateLimitMax:
            if not self.quietMode:
                print(f"{Sex.B_RED}[RATE LIMIT]{Sex.END} {Sex.WHITE}{username}{Sex.END} {Sex.GRAY}exceeded {self.rateLimitMax}/min{Sex.END}")
            self.writeLog(f"[RATE LIMIT] {username} exceeded {self.rateLimitMax}/min")
            return False

        self.messageRates[username].append(now)
        return True

    def setupUPnP(self):
        if not self.upnpEnabled:
            return False

        try:
            upnp = miniupnpc.UPnP()
            upnp.discoverdelay = 200

            if not self.quietMode:
                print(f"{Sex.GRAY}[upnp] [discovering devices]{Sex.END}")

            ndevices = upnp.discover()
            if ndevices == 0:
                print(f"{Sex.B_RED}[upnp] [no devices found]{Sex.END}")
                return False

            upnp.selectigd()
            externalIP = upnp.externalipaddress()
            upnp.addportmapping(
                self.port,
                'TCP',
                upnp.lanaddr,
                self.port,
                'p2p chat node',
                ''
            )

            self.upnpMapping = upnp

            if not self.quietMode:
                print(f"{Sex.GRAY}[upnp] Port{Sex.END}          :: {Sex.CYAN}{self.port} opened{Sex.END}")
                print(f"{Sex.GRAY}[upnp] External IP{Sex.END}   :: {Sex.CYAN}{externalIP}{Sex.END}")

            self.writeLog(f"[upnp] port forwarding ON: {externalIP}:{self.port}")
            return True
        except Exception as e:
            print(f"{Sex.B_RED}[upnp] [failed] {Sex.END}{Sex.N_RED}{e}{Sex.END}")
            return False

    def closeUPnP(self):
        if self.upnpMapping:
            try:
                self.upnpMapping.deleteportmapping(self.port, 'TCP')
                if not self.quietMode:
                    print(f"{Sex.GRAY}[upnp] Port {self.port} closed{Sex.END}")
            except:
                pass


    def initialMedia(self):
        if not self.mediaEnabled:
            return

        self.mediaDownload.mkdir(exist_ok=True)
        if not self.quietMode:
            print(f"{Sex.GRAY}[Media] downloads folder: {Sex.CYAN}/{self.mediaDownload}{Sex.END}")

    def sendFile(self, filepath, targetPeer):
        try:
            filepath = Path(filepath).expanduser().resolve()
            if not filepath.exists():
                print(f"{Sex.GRAY}[filePath not exist] {filepath}{Sex.END}")
                return False
            filesize = filepath.stat().st_size
            transferID = hashlib.sha256(f"{filepath.name}{time.time()}".encode()).hexdigest()[:16]
            mimeType = mimetypes.guess_type(filepath)[0] or 'application/octet-stream'
            peerAddr = None

            with self.peersLock:
                for addr, peer in self.peers.items():
                    if peer['username'] == targetPeer and peer['connected']:
                        peerAddr = addr
                        break
            if not peerAddr:
                print(f"{Sex.B_RED}[Media] [Peer not found] {targetPeer}{Sex.END}")
                return False

            offerMsg = {
                'type': 'media_offer',
                'transfer_id': transferID,
                'filename': filepath.name,
                'filesize': filesize,
                'mime_type': mimeType,
                'from': self.username
            }

            self.sendMsg(self.peers[peerAddr]['conn'], offerMsg)

            with self.mediaLock:
                self.mediaTransfer[transferID] = {
                    'filepath': filepath,
                    'peer': targetPeer,
                    'peerAddr': peerAddr,
                    'filesize': filesize,
                    'sent': 0,
                    'status': 'pending'
                }

            print(f"{Sex.GRAY}[Media] offer sent to {Sex.WHITE}{targetPeer}{Sex.END}")
            print(f"{Sex.GRAY} File  :: {filepath.name} ({self.formatSize(filesize)}){Sex.END}")
            return True
        except Exception as e:
            print(f"{Sex.B_RED}[Media] [error]{Sex.END}{e}")
            return False


    def sendFolder(self, folderPath, targetPeer):
        try:
            import zipfile
            folderPath = Path(folderPath).expanduser().resolve()

            if not folderPath.is_dir():
                print(f"{Sex.B_RED}[Media] [Not a folder] :: {folderPath}{Sex.END}")
                return False

            zipPath = Path(f"/tmp/{folderPath.name}.zip")
            print(f"{Sex.GRAY}[Media] compressing folder... {Sex.END}")

            with zipfile.ZipFile(zipPath, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for file in folderPath.rglob('*'):
                    if file.is_file():
                        zipf.write(file, file.relative_to(folderPath.parent))

            result = self.sendFile(zipPath, targetPeer)
            zipPath.unlink()
            return result
        except Exception as e:
            print(f"{Sex.B_RED}[Media] [err] {e}{Sex.END}")
            return False

    def acceptTransfer(self, transferID):
        if transferID not in self.pendingTransfers:
            print(f"{Sex.B_RED}[Media] Transfer not found{Sex.END}")
            return False

        transfer = self.pendingTransfers[transferID]
        isDrop = transfer.get('is_drop', False)

        if isDrop and transferID in self.dropTimers:
            self.dropTimers[transferID].cancel()
            del self.dropTimers[transferID]

        acceptMsg = {
            'type': 'media_accept',
            'transfer_id': transferID
        }

        peerAddr = None
        with self.peersLock:
            for addr, peer in self.peers.items():
                if peer['username'] == transfer['from']:
                    peerAddr = addr
                    break

        if peerAddr:
            self.sendMsg(self.peers[peerAddr]['conn'], acceptMsg)
            
            if isDrop:
                print(f"{Sex.CYAN}[Drop] Accepting transfer...{Sex.END}")
            else:
                print(f"{Sex.CYAN}[Media] Accepting transfer...{Sex.END}")

            with self.mediaLock:
                self.mediaTransfer[transferID] = {
                    'filename': transfer['filename'],
                    'filesize': transfer['filesize'],
                    'received': 0,
                    'chunks': [],
                    'status': 'receiving',
                    'is_drop': isDrop
                }

            del self.pendingTransfers[transferID]
            return True

        return False

    def rejectTransfer(self, transferID):
        if transferID not in self.pendingTransfers:
            print(f"{Sex.B_RED}[Media] Transfer not found{Sex.END}")
            return False

        transfer = self.pendingTransfers[transferID]

        rejectMsg = {
            'type': 'media_reject',
            'transfer_id': transferID
        }


        peerAddr = None
        with self.peersLock:
            for addr, peer in self.peers.items():
                if peer['username'] == transfer['from']:
                    peerAddr = addr
                    break

        if peerAddr:
            self.sendMsg(self.peers[peerAddr]['conn'], rejectMsg)

        print(f"{Sex.GRAY}[Media] Transfer rejected{Sex.END}")
        del self.pendingTransfers[transferID]
        return True

    def sendFileChunks(self, transferID):
        #if transferID not in self.mediaTransfer:
            #return

        transfer = self.mediaTransfer.get(transferID) or self.dropTransfers.get(transferID)
        if not transfer:
            return

        #transfer = self.mediaTransfer[transferID]

        if transfer['status'] != 'accepted':
            return

        try:
            CHUNK_SIZE = 64 * 1024  # 64KB chunks

            with open(transfer['filepath'], 'rb') as f:
                chunkNum = 0

                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break

                    chunkMsg = {
                        'type': 'media_chunk',
                        'transfer_id': transferID,
                        'chunk_num': chunkNum,
                        'data': base64.b64encode(chunk).decode('utf-8'),
                        'is_last': len(chunk) < CHUNK_SIZE
                    }

                    self.sendMsg(self.peers[transfer['peerAddr']]['conn'], chunkMsg)

                    transfer['sent'] += len(chunk)
                    chunkNum += 1

                    # Progress
                    progress = (transfer['sent'] / transfer['filesize']) * 100
                    if chunkNum % 10 == 0:  #  cada 10 chunks
                        print(f"\r{Sex.GRAY}[Media] Sending: {progress:.1f}%{Sex.END}", end='', flush=True)

            print(f"\n{Sex.CYAN}[Media] Transfer complete!{Sex.END}")

            with self.mediaLock:
                transfer['status'] = 'completed'

        except Exception as e:
            print(f"\n{Sex.B_RED}[Media] Transfer failed: {e}{Sex.END}")
            with self.mediaLock:
                transfer['status'] = 'failed'

    def receiveChunk(self, transferID, chunkNum, data, isLast):
        if transferID not in self.mediaTransfer:
            return

        transfer = self.mediaTransfer[transferID]

        try:
            chunkData = base64.b64decode(data)

            transfer['chunks'].append((chunkNum, chunkData))
            transfer['received'] += len(chunkData)

            progress = (transfer['received'] / transfer['filesize']) * 100
            print(f"\r{Sex.GRAY}[Media] Receiving: {progress:.1f}%{Sex.END}", end='', flush=True)

            if isLast:
                print()  # Nw línea
                self.assembleFile(transferID)

        except Exception as e:
            print(f"\n{Sex.B_RED}[Media] Chunk error: {e}{Sex.END}")

    def assembleFile(self, transferID):
        transfer = self.mediaTransfer[transferID]

        try:
            # Ordenar chunks
            transfer['chunks'].sort(key=lambda x: x[0])

            # Escribir archivo
            outputPath = self.mediaDownload / transfer['filename']

            with open(outputPath, 'wb') as f:
                for _, chunkData in transfer['chunks']:
                    f.write(chunkData)

            print(f"{Sex.CYAN}[Media] File saved: {Sex.WHITE}{outputPath}{Sex.END}")
            self.writeLog(f"[Media] Downloaded: {transfer['filename']} ({transfer['filesize']} bytes)")

            with self.mediaLock:
                del self.mediaTransfer[transferID]

        except Exception as e:
            print(f"{Sex.B_RED}[Media] Assembly failed: {e}{Sex.END}")

    def formatSize(self, bytes):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes < 1024:
                return f"{bytes:.1f} {unit}"
            bytes /= 1024
        return f"{bytes:.1f} TB" 

    def sendDrop(self, filepath, targetPeer, timeLimit=60):
        try:
            filepath = Path(filepath).expanduser().resolve()
            
            if filepath.is_dir():
                import zipfile
                zipPath = Path(f"/tmp/{filepath.name}_drop.zip")
                
                with zipfile.ZipFile(zipPath, 'w', zipfile.ZIP_DEFLATED) as zipf:
                    for file in filepath.rglob('*'):
                        if file.is_file():
                            zipf.write(file, file.relative_to(filepath.parent))
                filepath = zipPath
                
            if not filepath.exists():
                print(f"{Sex.B_RED}[Drop] Path not found{Sex.END}")
                return False
                
            filesize = filepath.stat().st_size
            transferID = hashlib.sha256(f"drop_{filepath.name}{time.time()}".encode()).hexdigest()[:16]
            mimeType = mimetypes.guess_type(filepath)[0] or 'application/octet-stream'
            
            peerAddr = None
            with self.peersLock:
                for addr, peer in self.peers.items():
                    if peer['username'] == targetPeer and peer['connected']:
                        peerAddr = addr
                        break
                        
            if not peerAddr:
                print(f"{Sex.B_RED}[Drop] Peer not found{Sex.END}")
                return False
                
            offerMsg = {
                'type': 'drop_offer',
                'transfer_id': transferID,
                'filename': filepath.name,
                'filesize': filesize,
                'mime_type': mimeType,
                'from': self.username,
                'time_limit': timeLimit
            }
            
            self.sendMsg(self.peers[peerAddr]['conn'], offerMsg)
            
            with self.mediaLock:
                self.dropTransfers[transferID] = {
                    'filepath': filepath,
                    'peer': targetPeer,
                    'peerAddr': peerAddr,
                    'filename': filepath.name,
                    'filesize': filesize,
                    'sent': 0,
                    'status': 'pending',
                    'deadline': time.time() + timeLimit
                }
                
            timer = threading.Timer(timeLimit, self.expireDrop, args=(transferID,))
            timer.daemon = True
            timer.start()
            self.dropTimers[transferID] = timer
            
            print(f"{Sex.CYAN}[Drop] Offer sent to {Sex.WHITE}{targetPeer}{Sex.END}")
            print(f"{Sex.GRAY} File: {filepath.name} ({self.formatSize(filesize)}){Sex.END}")
            print(f"{Sex.GRAY} Expires in: {timeLimit}s{Sex.END}")
            return True
            
        except Exception as e:
            print(f"{Sex.B_RED}[Drop] Error: {e}{Sex.END}")
            return False


    def expireDrop(self, transferID):
        with self.mediaLock:
            if transferID in self.dropTransfers:
                transfer = self.dropTransfers[transferID]
                if transfer['status'] == 'pending':
                    print(f"{Sex.GRAY}[Drop] Transfer expired: {transfer.get('filename', 'unknown')}{Sex.END}")
                    
                    if str(transfer['filepath']).endswith('_drop.zip'):
                        try:
                            transfer['filepath'].unlink()
                        except:
                            pass
                            
                del self.dropTransfers[transferID]
                
        if transferID in self.dropTimers:
            del self.dropTimers[transferID]
            
        if transferID in self.pendingTransfers:
            del self.pendingTransfers[transferID]

        if not self.quietMode:
            print(f"{Sex.B_RED}[drop {Sex.END}{Sex.WHITE}{transfer.get('filename', 'unknown')}{Sex.END}{Sex.B_RED} expired]{Sex.END}")

    def genPrivateKey(self, targetUser):
        with self.privateKeysLock:
            keyPair = f"{self.username}:{targetUser}"
            reverseKeyPair = f"{targetUser}:{self.username}"
            
            if keyPair in self.privateKeys:
                return self.privateKeys[keyPair]
            elif reverseKeyPair in self.privateKeys:
                return self.privateKeys[reverseKeyPair]
            else:
                
                users = sorted([self.username, targetUser]) 
                keyMaterial = f"{users[0]}:{users[1]}".encode() + self.authCredential
                newKey = hashlib.sha256(keyMaterial).digest() + hashlib.sha256(keyMaterial + b"salt").digest()
                newKey = newKey[:120]  # Tomar 120 bytes
                
                self.privateKeys[keyPair] = newKey
                self.privateKeys[reverseKeyPair] = newKey
                return newKey


    def encryptPrivateMsg(self, msg, key):
        if not USE_C_LIBS:
            keyStr = key.hex()
            xored = bytes(b ^ ord(keyStr[i % len(keyStr)]) for i, b in enumerate(msg.encode('utf-8')))
            return base64.b64encode(xored).decode()
            
        encrypted = CryptoMessage()
        try:
            cryptoKey = (c_uint8 * 32)(*hashlib.sha256(key).digest())
            plaintext = msg.encode('utf-8')
            ptArray = (c_uint8 * len(plaintext))(*plaintext)
            
            if cryptoLib.cryptoEncryptMessage(ptArray, len(plaintext), cryptoKey, byref(encrypted)) != 0:
                keyStr = key.hex()
                xored = bytes(b ^ ord(keyStr[i % len(keyStr)]) for i, b in enumerate(msg.encode('utf-8')))
                return base64.b64encode(xored).decode()
                
            ctBytes = bytes(encrypted.ciphertext[:encrypted.ciphertextLen])
            nonceBytes = bytes(encrypted.nonce)
            tagBytes = bytes(encrypted.tag)
            combined = ctBytes + nonceBytes + tagBytes
            
            return base64.b64encode(combined).decode('utf-8')
            
        except Exception as e:
            keyStr = key.hex()
            xored = bytes(b ^ ord(keyStr[i % len(keyStr)]) for i, b in enumerate(msg.encode('utf-8')))
            return base64.b64encode(xored).decode()
        finally:
            if encrypted.ciphertext:
                cryptoLib.cryptoFreeMessage(byref(encrypted))

    def decryptPrivateMsg(self, encMsg, key):
        if not USE_C_LIBS:
            try:
                raw = base64.b64decode(encMsg.encode())
                keyStr = key.hex()
                data = bytes(b ^ ord(keyStr[i % len(keyStr)]) for i, b in enumerate(raw))
                return data.decode('utf-8')
            except:
                return "[decrypt error]"
                
        plaintext = POINTER(c_uint8)()
        try:
            combined = base64.b64decode(encMsg.encode('utf-8'))
            
            if len(combined) < 28:
                raw = combined
                keyStr = key.hex()
                data = bytes(b ^ ord(keyStr[i % len(keyStr)]) for i, b in enumerate(raw))
                return data.decode('utf-8')
                
            ctLen = len(combined) - 28
            cryptoKey = (c_uint8 * 32)(*hashlib.sha256(key).digest())
            
            encrypted = CryptoMessage()
            encrypted.ciphertext = (c_uint8 * ctLen)(*combined[:ctLen])
            encrypted.ciphertextLen = ctLen
            encrypted.nonce = (c_uint8 * 12)(*combined[ctLen:ctLen+12])
            encrypted.tag = (c_uint8 * 16)(*combined[ctLen+12:ctLen+28])
            
            ptLen = c_size_t()
            
            if cryptoLib.cryptoDecryptMessage(byref(encrypted), cryptoKey, byref(plaintext), byref(ptLen)) != 0:
                keyStr = key.hex()
                raw = combined
                data = bytes(b ^ ord(keyStr[i % len(keyStr)]) for i, b in enumerate(raw))
                return data.decode('utf-8')
                
            result = bytes(plaintext[:ptLen.value]).decode('utf-8')
            return result
            
        except Exception as e:
            return "[decrypt error]"
        finally:
            if plaintext:
                try:
                    cryptoLib.cryptoSecureZero(plaintext, ptLen.value if 'ptLen' in locals() else 0)
                except:
                    pass

    def sendPrivateMessage(self, targetUser, content):
        peerAddr = None
        with self.peersLock:
            for addr, peer in self.peers.items():
                if peer['username'] == targetUser and peer['connected']:
                    peerAddr = addr
                    break
                    
        if not peerAddr:
            print(f"{Sex.B_RED}[Private] User {targetUser} not connected{Sex.END}")
            return False
            
        privateKey = self.genPrivateKey(targetUser)
        encryptedContent = self.encryptPrivateMsg(content, privateKey)
        
        timestamp = datetime.now().isoformat()
        msgId = self.msgId(self.username, encryptedContent, timestamp)
        
        msg = {
            'type': 'private',
            'id': msgId,
            'from': self.username,
            'to': targetUser,
            'message': encryptedContent,
            'timestamp': timestamp
        }
        
        try:
            self.sendMsg(self.peers[peerAddr]['conn'], msg)
            
            try:
                dt = datetime.fromisoformat(timestamp)
                timeStr = dt.strftime('%H:%M:%S')
            except:
                timeStr = ''
                
            print(f"{Sex.GRAY}[{timeStr}] {Sex.N_CYAN}[Private→{targetUser}]{Sex.END} {Sex.GRAY}::{Sex.END} {content}")
            return True
        except:
            print(f"{Sex.B_RED}[Private] Failed to send{Sex.END}")
            return False

    def sendMsg(self, conn, msg):
        msgJson = json.dumps(msg).encode('utf-8')
        length = len(msgJson).to_bytes(4, 'big')
        conn.sendall(length + msgJson)

    def recvMsg(self, conn):
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

    def msgId(self, username, content, timestamp):
        return hashlib.sha256(f"{username}{content}{timestamp}".encode()).hexdigest()[:16]

    def connectToPeer(self, peerAddr):
        #if self.myOnion and peerAddr == f"{self.myOnion}:{self.port}":
            #return False

        try:
            host, port = peerAddr.split(':')
            if host in self.blacklist:
                if not self.quietMode:
                    print(f"{Sex.B_RED}[BLOQUED]{Sex.END} {Sex.GRAY}{peerAddr}[blacklisted]{Sex.END}")
                self.writeLog(f"[BLOQUED] connection attemp from blacklisted peer: {peerAddr}")
                return False

            port = int(port)

            sock = socks.socksocket()
            sock.set_proxy(
                proxy_type=socks.SOCKS5,
                addr=self.proxyHost,
                port=self.proxyPort
            )
            sock.settimeout(None)
            sock.connect((host, port))
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

            import hashlib
            authHash = hashlib.sha224(self.authCredential).hexdigest()
            self.sendMsg(sock, {
                'type': 'auth',
                'username': self.username,
                'authHash': authHash,
                'credentialType': self.credentialType,
                'peer': True,
                'onion': self.myOnion,
                'fingerprint' : self.myFingerprint if hasattr(self, 'myFingerprint') and self.myFingerprint else None
            })

            response = self.recvMsg(sock)
            if not response or response.get('type') != 'auth_success':
                sock.close()
                return False

            peerUsername = response.get('username', 'unknown')
            peerFingerprint = response.get('fingerprint')

            if self.verifyEnabled and peerFingerprint:
                trustedFp = self.trustedFingerprints.get(peerUsername)

                if trustedFp:
                    if peerFingerprint == trustedFp:
                        print(f"{Sex.PURPLE}[VERIFIED]{Sex.END} {Sex.WHITE}{peerUsername}{Sex.END}")
                    else:
                        print(f"{Sex.B_RED}[WARNING]{Sex.END} {Sex.WHITE}{peerUsername}{Sex.END} {Sex.B_RED}FINGERPRINT MISMATCH!{Sex.END}")
                        print(f"{Sex.GRAY}Expected: {trustedFp}{Sex.END}")
                        print(f"{Sex.GRAY}Received: {peerFingerprint}{Sex.END}")
                else:
                    print(f"{Sex.GRAY}[UNVERIFIED] {peerUsername} :: {peerFingerprint}{Sex.END}")
                    print(f"{Sex.GRAY}Verify then: {Sex.CYAN}/verify {peerUsername} {peerFingerprint}{Sex.END}")


            with self.peersLock:
                self.peers[peerAddr] = {
                    'conn': sock,
                    'username': peerUsername,
                    'connected': True,
                    'lastSeen': time.time()
                }

            if not self.quietMode:
                print(f"{Sex.GRAY}[p+] {peerAddr}{Sex.END}")
            self.writeLog(f"[p+] connected to {peerAddr}")

            threading.Thread(target=self.handlePeerMessages, args=(peerAddr,), daemon=True).start()

            self.sendMsg(sock, {'type': 'peer_request'})

            return True
        except Exception as e:
            print(f"{Sex.B_RED}[err] failed {peerAddr} :: {e}{Sex.END}")
            return False

    def handlePeerMessages(self, peerAddr):
        peer = self.peers.get(peerAddr)
        if not peer:
            return

        conn = peer['conn']

        try:
            while self.running and peer['connected']:
                msg = self.recvMsg(conn)
                if msg is None:
                    break

                peer['lastSeen'] = time.time()
                self.processP2PMessage(msg, peerAddr)
        except:
            pass
        finally:
            with self.peersLock:
                if peerAddr in self.peers:
                    self.peers[peerAddr]['connected'] = False

            if not self.quietMode:
                print(f"{Sex.GRAY}[p-] {peerAddr}{Sex.END}")
            self.writeLog(f"[p-] disconnected from {peerAddr}")

    def processP2PMessage(self, msg, fromPeer):
        msgType = msg.get('type')

        if msgType == 'chat':
            msgId = msg.get('id')

            if msg.get('noise'):
                return

            with self.seenMessagesLock:
                if msgId in self.seenMessages:
                    return
                self.seenMessages.add(msgId)

            username = msg.get('username')

            if not self.checkRateLimit(username):
                return

            if username in self.blockedUsers:
                return

            if username in self.mutedUsers:
                return

            self.messageHistory.append(msg)

            if self.paranMode:
                self.scheduleDestruct(msgId)

            content = msg.get('message')
            if msg.get('crypto') and self.xorKey:
                try:
                    content = self.decryptMessages(content)
                except:
                    content = "[decrypt error]"

            timestamp = msg.get('timestamp', '')

            if self.stealthMode or not timestamp:
                print(f"{Sex.PURPLE}{username}{Sex.END}{Sex.GRAY} ::{Sex.END} {content}")
            else:
                try:
                    dt = datetime.fromisoformat(timestamp)
                    timeStr = dt.strftime('%H:%M:%S')
                except:
                    timeStr = ''
                self.writeLog(f"{username} :: {content}")  # [WARN LOG]
                print(f"{Sex.WHITE}{Sex.GRAY}[{timeStr}]{Sex.END} {Sex.PURPLE}{username}{Sex.END}{Sex.GRAY} ::{Sex.END} {content}")

            if msg.get('ttl', 0) > 0:
                msg['ttl'] -= 1
                self.broadcast(msg, exclude=fromPeer)


        elif msgType == 'peer_request':
            peerList = list(self.knownPeers)
            self.sendMsg(self.peers[fromPeer]['conn'], {
                'type': 'peer_list',
                'peers': peerList
            })

        elif msgType == 'peer_list':
            newPeers = msg.get('peers', [])
            for peer in newPeers:
                with self.knownPeersLock:
                    shouldConnect = (peer not in self.knownPeers and
                                     peer != self.myOnion and
                                     len(self.peers) < MAX_PEERS)
                    if peer not in self.knownPeers:
                        self.knownPeers.add(peer)

                if shouldConnect:
                    threading.Thread(target=self.connectToPeer, args=(peer,), daemon=True).start()
                #if peer not in self.knownPeers and peer != self.myOnion:
                    #self.knownPeers.add(peer)
                    #if len(self.peers) < MAX_PEERS:
                        #threading.Thread(target=self.connectToPeer, args=(peer,), daemon=True).start()

        elif msgType == 'peer_announce':
            newPeer = msg.get('peer')
            if newPeer:
                with self.knownPeersLock:
                    if newPeer not in self.knownPeers:
                        self.knownPeers.add(newPeer)
                        shouldBroadcast = msg.get('ttl', 0) > 0

                if shouldBroadcast:
                    msg['ttl'] -= 1
                    self.broadcast(msg, exclude=fromPeer)
            #if newPeer and newPeer not in self.knownPeers:
                #self.knownPeers.add(newPeer)
                #if msg.get('ttl', 0) > 0:
                    #msg['ttl'] -= 1
                    #self.broadcast(msg, exclude=fromPeer)

        elif msgType == 'gossip':
            peers = msg.get('peers', [])
            with self.knownPeersLock:
                for peer in peers:
                    if peer not in self.knownPeers and peer != self.myOnion:
                        self.knownPeers.add(peer)

        elif msgType == 'heartbeat':
            pass

        elif msgType == 'fingerprint_request':
            if self.verifyEnabled:
                self.sendMsg(self.peers[fromPeer]['conn'], {
                    'type': 'fingerprint_request',
                    'fingerprint': self.myFingerprint
                })

        elif msgType == 'fingerprint_response':
            username = msg.get('username')
            receivedFp = msg.get('fingerprint')

            trustedFp = self.trustedFingerprints.get(username)

            if trustedFp:
                if receivedFp == trustedFp:
                    print(f"{Sex.PURPLE}[VERIFIED]{Sex.END} {Sex.WHITE}{username}{Sex.END}")
                else:
                    print(f"{Sex.B_RED}WARNING{Sex.END} {Sex.WHITE}{username}{Sex.END} {Sex.B_RED}FINGERPRINT MISMATCH!{Sex.END}")
                    print(f"{Sex.GRAY}Expected: {trustedFp}{Sex.END}")
                    print(f"{Sex.GRAY}Received: {receivedFp}{Sex.END}")
            else:
                print(f"{Sex.GRAY}[UNVERIFIED] {username} :: {receivedFp}{Sex.END}")

        elif msgType == 'media_offer':
            transferID = msg.get('transfer_id')
            filename = msg.get('filename')
            filesize = msg.get('filesize')
            fromUser = msg.get('from')

            self.pendingTransfers[transferID] = {
                'from': fromUser,
                'filename': filename,
                'filesize': filesize,
                'id': transferID
            }

            print(f"\n{Sex.CYAN}[Media] Incoming file from {Sex.WHITE}{fromUser}{Sex.END}")
            print(f"{Sex.GRAY}  File: {filename} ({self.formatSize(filesize)}){Sex.END}")
            print(f"{Sex.GRAY}  ID: {transferID}{Sex.END}")
            print(f"{Sex.PURPLE}  /accept {transferID}{Sex.END} or {Sex.PURPLE}/reject {transferID}{Sex.END}")

            self.writeLog(f"[MEDIA] offer received  : {filename} from {fromUser}")

        elif msgType == 'media_accept':
            transferID = msg.get('transfer_id')

            if transferID in self.mediaTransfer:
                self.mediaTransfer[transferID]['status'] = 'accepted'
                print(f"{Sex.CYAN}[Media] Transfer accepted! [starting] {Sex.END}")

                threading.Thread(
                    target=self.sendFileChunks,
                    args=(transferID,),
                    daemon=True
                ).start()
            elif transferID in self.dropTransfers:
                self.dropTransfers[transferID]['status'] = 'accepted'
                print(f"{Sex.CYAN}[Drop] Transfer accepted! [starting] {Sex.END}")

                threading.Thread(
                    target=self.sendFileChunks,
                    args=(transferID,),
                    daemon=True
                ).start()

        elif msgType == 'media_reject':
            transferID = msg.get('transfer_id')

            if transferID in self.mediaTransfer:
                print(f"{Sex.B_RED}[Media] Transfer rejected by peer {Sex.END}")
                with self.mediaLock:
                    del self.mediaTransfer[transferID]
            elif transferID in self.dropTransfers:
                print(f"{Sex.B_RED}[Drop] Transfer rejected by peer {Sex.END}")
                with self.mediaLock:
                    del self.dropTransfers[transferID]
                    
                if transferID in self.dropTimers:
                    self.dropTimers[transferID].cancel()
                    del self.dropTimers[transferID]

        elif msgType == 'drop_offer':
            transferID = msg.get('transfer_id')
            filename = msg.get('filename')
            filesize = msg.get('filesize')
            fromUser = msg.get('from')
            timeLimit = msg.get('time_limit', 60)
            
            self.pendingTransfers[transferID] = {
                'from': fromUser,
                'filename': filename,
                'filesize': filesize,
                'id': transferID,
                'is_drop': True,
                'deadline': time.time() + timeLimit
            }
            
            timer = threading.Timer(timeLimit, self.expireDrop, args=(transferID,))
            timer.daemon = True
            timer.start()
            self.dropTimers[transferID] = timer
            
            print(f"\n{Sex.N_RED}[Drop] Temporary file from {Sex.WHITE}{fromUser}{Sex.END}")
            print(f"{Sex.GRAY}  File: {filename} ({self.formatSize(filesize)}){Sex.END}")
            print(f"{Sex.GRAY}  ID: {transferID}{Sex.END}")
            print(f"{Sex.B_RED}  Expire: {timeLimit}s{Sex.END}")
            print(f"{Sex.PURPLE}  /accept {transferID}{Sex.END} or {Sex.PURPLE}/reject {transferID}{Sex.END}")
            
            self.writeLog(f"[DROP] offer received: {filename} from {fromUser} (expires in {timeLimit}s)")

        elif msgType == 'private':
            fromUser = msg.get('from')
            toUser = msg.get('to')
            
            if toUser != self.username:
                return
                
            if fromUser in self.blockedUsers or fromUser in self.mutedUsers:
                return
                
            encryptedContent = msg.get('message')
            privateKey = self.genPrivateKey(fromUser)
            
            try:
                content = self.decryptPrivateMsg(encryptedContent, privateKey)
            except:
                content = "[decrypt error]"
                
            timestamp = msg.get('timestamp', '')
            
            try:
                dt = datetime.fromisoformat(timestamp)
                timeStr = dt.strftime('%H:%M:%S')
            except:
                timeStr = ''
                
            print(f"{Sex.GRAY}[{timeStr}] {Sex.N_CYAN}[Private←{fromUser}]{Sex.END} {Sex.GRAY}::{Sex.END} {content}")

        elif msgType == 'media_chunk':
            transferID = msg.get('transfer_id')
            chunkNum = msg.get('chunk_num')
            data = msg.get('data')
            isLast = msg.get('is_last', False)

            self.receiveChunk(transferID, chunkNum, data, isLast)

        if self.relayMode and msgType == 'chat':
            self.relayStats['messages'] += 1
            self.relayStats['bytes'] += len(json.dumps(msg))
            self.relayStats['peers'].add(username)

            self.writeLog(f"[Relay] forwaring message from {username}")


    def broadcast(self, msg, exclude=None):
        with self.peersLock:
            for peerAddr, peer in list(self.peers.items()):
                if peerAddr != exclude and peer['connected']:
                    try:
                        self.sendMsg(peer['conn'], msg)
                    except:
                        peer['connected'] = False

    def sendChatMessage(self, content):
        timestamp = datetime.now().isoformat()
        msgId = self.msgId(self.username, content, timestamp)

        encryptedContent = content
        if self.xorKey:
            encryptedContent = self.encryptMessage(content)

        msg = {
            'type': 'chat',
            'id': msgId,
            'username': self.username,
            'message': encryptedContent,
            'timestamp': timestamp,
            'ttl': 5,
            'crypto': bool(self.xorKey)
        }

        if self.stealthMode:
            msg = self.stealthMsg(msg)


        with self.seenMessagesLock:
            self.seenMessages.add(msgId)
        #self.seenMessages.add(msgId)
        self.messageHistory.append(msg)
        if self.paranMode:
            self.scheduleDestruct(msgId)

        self.broadcast(msg)

    def startServer(self):
        try:
            self.serverSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.serverSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.serverSock.bind(('127.0.0.1', self.port))
            self.serverSock.listen(10)

            if not self.quietMode:
                print(f"{Sex.GRAY}[server][Listening]{Sex.END} :: {Sex.CYAN}{self.port}{Sex.END}")
            self.writeLog(f"[SERVER] listening on port :: {self.port}")

            while self.running:
                try:
                    conn, addr = self.serverSock.accept()
                    threading.Thread(target=self.handleIncomingPeer, args=(conn, addr), daemon=True).start()
                except OSError:
                    break
        except Exception as e:
            print(f"{Sex.B_RED}[server] err :: {e}{Sex.END}")

    def handleIncomingPeer(self, conn, addr):
        try:
            authMsg = self.recvMsg(conn)
            if not authMsg or authMsg.get('type') != 'auth':
                conn.close()
                return

            peerUsername = authMsg.get('username')
            if self.whitelist and peerUsername not in self.whitelist:
                if not self.quietMode:
                    print(f"{Sex.B_RED}[REJECTED]{Sex.END} {Sex.GRAY}{peerUsername}(not in whitelist permissed){Sex.END}")
                self.writeLog(f"[REJECTED] {peerUsername} not in whitelist")
                self.sendMsg(conn, {'type': 'error', 'message': 'not whitelist'})
                conn.close()
                return
            #peerPassword = authMsg.get('password')
            peerOnion = authMsg.get('onion')

            if peerUsername == self.username:
                conn.close()
                return

            import hashlib
            peerAuthHash = authMsg.get('authHash')
            peerCredType = authMsg.get('credentialType', 'password')

            if peerCredType != self.credentialType:
                self.sendMsg(conn, {
                    'type': 'error',
                    'message': f'credential mismatch (you: {self.credentialType}, peer: {peerCredType}'})
                conn.close()
                return

            expectedHash = hashlib.sha224(self.authCredential).hexdigest()

            if peerAuthHash != expectedHash:
                self.sendMsg(conn, {'type': 'error', 'message': 'invalid credentials'})
                conn.close()
                return

            peerFingerprint = authMsg.get('fingerprint')
            if self.verifiedUsers and peerFingerprint:
                trustedFp = self.trustedFingerprints.get(peerUsername)
                if trustedFp:
                    if peerFingerprint == trustedFp:
                        print(f"{Sex.PURPLE}[VERIFIED]{Sex.END} {Sex.WHITE}{peerUsername}{Sex.END}")
                    else:
                        print(f"{Sex.B_RED}[WARNING]{Sex.END} {Sex.WHITE}{peerUsername}{Sex.END} {Sex.B_RED}FINGERPRINT MISMATCH!{Sex.END}")
                        print(f"{Sex.GRAY}Expected: {trustedFp}{Sex.END}")
                        print(f"{Sex.GRAY}Received: {peerFingerprint}{Sex.END}")
                else:
                    print(f"{Sex.GRAY}[UNVERIFIED] {peerUsername} :: {peerFingerprint}{Sex.END}")
                    print(f"{Sex.GRAY}Verify then: {Sex.CYAN}/verify {peerUsername} {peerFingerprint}{Sex.END}")


            self.sendMsg(conn, {
                'type': 'auth_success',
                'username': self.username,
                'onion': self.myOnion,
                'fingerprint': self.myFingerprint if hasattr(self, 'myFingerprint') and self.myFingerprint else None
            })

            if peerOnion:
                peerAddr = f"{peerOnion}:{self.port}"
                with self.peersLock:
                    self.peers[peerAddr] = {
                        'conn': conn,
                        'username': peerUsername,
                        'connected': True,
                        'lastSeen': time.time()
                    }

                if not self.quietMode:
                    print(f"{Sex.GRAY}[p+] incoming :: {peerUsername}{Sex.END}")
                self.writeLog(f"[p+ incoming connection from :: {peerUsername}]")

                threading.Thread(target=self.handlePeerMessages, args=(peerAddr,), daemon=True).start()
        except Exception as e:
            print(f"{Sex.B_RED}[err] incoming err :: {e}{Sex.END}")
            conn.close()

    def discoveryLoop(self):
        while self.running:
            time.sleep(GOSSIP_INTERVAL)

            with self.peersLock:
                activePeers = [p for p in self.peers.values() if p['connected']]

            if len(activePeers) < 3:
                for peer in list(self.knownPeers)[:5]:
                    if peer not in self.peers:
                        threading.Thread(target=self.connectToPeer, args=(peer,), daemon=True).start()

            for peerAddr, peer in list(self.peers.items()):
                if peer['connected']:
                    try:
                        self.sendMsg(peer['conn'], {
                            'type': 'gossip',
                            'peers': list(self.knownPeers)[:10]
                        })
                    except:
                        peer['connected'] = False

    def heartbeatLoop(self):
        while self.running:
            time.sleep(HEARTBEAT_INTERVAL)

            with self.peersLock:
                for peerAddr, peer in list(self.peers.items()):
                    if peer['connected']:
                        try:
                            self.sendMsg(peer['conn'], {'type': 'heartbeat'})
                        except:
                            peer['connected'] = False

    def cleanupLoop(self):
        while self.running:
            time.sleep(60)

            now = time.time()
            with self.peersLock:
                for peerAddr, peer in list(self.peers.items()):
                    if now - peer['lastSeen'] > self.peerTimeout:
                    #if now - peer['lastSeen'] > 120:
                        peer['connected'] = False
                        if not self.quietMode:
                            print(f"{Sex.GRAY}[timeout] {peerAddr}{Sex.END}")
                        self.writeLog(f"[TIMEOUT] peer time out: {peerAddr}")

    # XOR
    def xorCipher(self, data: str, key: str) -> str:
        return ''.join(
                chr(ord(c) ^ ord(key[i % len(key)]))
                for i, c in enumerate(data)
        )

    def encodeXor(self, msg: str, key: str) -> str:
        xored = self.xorCipher(msg, key)
        return base64.b64encode(xored.encode('latin1')).decode('utf-8')

    def decodeXor(self, msg: str, key: str) -> str:
        raw = base64.b64decode(msg.encode('utf-8')).decode('latin1')
        return self.xorCipher(raw, key)



    # modules crypto CHACHA POLY
    def encryptMessage(self, msg: str) -> str:
        encryptKey = self.xorKey if self.xorKey else self.authCredential
        if not USE_C_LIBS or not encryptKey:
            keyStr = encryptKey.hex() if isinstance(encryptKey, bytes) else str(encryptKey)
            return self.encodeXor(msg, keyStr) if encryptKey else msg

        encrypted = CryptoMessage()
        try:
            key = (c_uint8 * 32)()
            if isinstance(encryptKey, bytes) and len(encryptKey) == 32 and self.credentialType == 'key':
                key = (c_uint8 * 32)(*encryptKey)
                needsSalt = False
            else:
                salt = (c_uint8 * 32)()
                if cryptoLib.cryptoRandomBytes(salt, 32) != 0:
                    keyStr = encryptKey.hex() if isinstance(encryptKey, bytes) else str(encryptKey)
                    return self.encodeXor(msg, keyStr)

                result = CryptoHash()
                keyStr = encryptKey.decode() if isinstance(encryptKey, bytes) else str(encryptKey)

                if cryptoLib.cryptoHashPassword(
                    keyStr.encode('utf-8'),
                    len(keyStr),
                    salt,
                    byref(result)
                ) != 0:
                    return self.encodeXor(msg, keyStr)

                key = (c_uint8 * 32)(*result.hash)
                needsSalt = True  # Password derivada necesita salt

            plaintext = msg.encode('utf-8')
            ptArray = (c_uint8 * len(plaintext))(*plaintext)

            if cryptoLib.cryptoEncryptMessage(
                ptArray,
                len(plaintext),
                key,
                byref(encrypted)
            ) != 0:
                keyStr = encryptKey.hex() if isinstance(encryptKey, bytes) else str(encryptKey)
                return self.encodeXor(msg, keyStr)

            ctBytes = bytes(encrypted.ciphertext[:encrypted.ciphertextLen])
            nonceBytes = bytes(encrypted.nonce)
            tagBytes = bytes(encrypted.tag)

            # incluir salt si es password
            if needsSalt:
                saltBytes = bytes(salt)
                combined = ctBytes + nonceBytes + tagBytes + saltBytes
            else:
                combined = ctBytes + nonceBytes + tagBytes

            return base64.b64encode(combined).decode('utf-8')

        except Exception as e:
            keyStr = encryptKey.hex() if isinstance(encryptKey, bytes) else str(encryptKey)
            return self.encodeXor(msg, keyStr)
        finally:
            if encrypted.ciphertext:
                cryptoLib.cryptoFreeMessage(byref(encrypted))

    def decryptMessages(self, msg: str) -> str:
        decryptKey = self.xorKey if self.xorKey else self.authCredential

        if not USE_C_LIBS or not decryptKey:
            keyStr = decryptKey.hex() if isinstance(decryptKey, bytes) else str(decryptKey)
            return self.decodeXor(msg, keyStr) if decryptKey else msg

        plaintext = POINTER(c_uint8)()
        try:
            combined = base64.b64decode(msg.encode('utf-8'))

            key = (c_uint8 * 32)()

            # Detectar formato
            if isinstance(decryptKey, bytes) and len(decryptKey) == 32 and self.credentialType == 'key':
                # Formato: [ciphertext][nonce][tag] (sin salt)
                if len(combined) < 28:
                    keyStr = decryptKey.hex()
                    return self.decodeXor(msg, keyStr)

                ctLen = len(combined) - 28
                key = (c_uint8 * 32)(*decryptKey)

            else:
                # Formato: [ciphertext][nonce][tag][salt]
                if len(combined) < 60:
                    keyStr = decryptKey.decode() if isinstance(decryptKey, bytes) else str(decryptKey)
                    return self.decodeXor(msg, keyStr)

                ctLen = len(combined) - 60
                saltBytes = combined[-32:]

                result = CryptoHash()
                salt = (c_uint8 * 32)(*saltBytes)
                keyStr = decryptKey.decode() if isinstance(decryptKey, bytes) else str(decryptKey)

                if cryptoLib.cryptoHashPassword(
                    keyStr.encode('utf-8'),
                    len(keyStr),
                    salt,
                    byref(result)
                ) != 0:
                    return self.decodeXor(msg, keyStr)

                key = (c_uint8 * 32)(*result.hash)

            encrypted = CryptoMessage()
            encrypted.ciphertext = (c_uint8 * ctLen)(*combined[:ctLen])
            encrypted.ciphertextLen = ctLen
            encrypted.nonce = (c_uint8 * 12)(*combined[ctLen:ctLen+12])
            encrypted.tag = (c_uint8 * 16)(*combined[ctLen+12:ctLen+28])

            ptLen = c_size_t()

            if cryptoLib.cryptoDecryptMessage(
                byref(encrypted),
                key,
                byref(plaintext),
                byref(ptLen)
            ) != 0:
                keyStr = decryptKey.hex() if isinstance(decryptKey, bytes) else str(decryptKey)
                return self.decodeXor(msg, keyStr)

            result = bytes(plaintext[:ptLen.value]).decode('utf-8')
            return result

        except Exception as e:
            keyStr = decryptKey.hex() if isinstance(decryptKey, bytes) else str(decryptKey)
            return self.decodeXor(msg, keyStr)
        finally:
            if plaintext:
                try:
                    cryptoLib.cryptoSecureZero(plaintext, ptLen.value if 'ptLen' in locals() else 0)
                except:
                    pass

    def inputLoop(self):
        import readline, atexit, signal

        encHistory = []
        hisKey = os.urandom(32)

        def encryptLine(line):
            if not USE_C_LIBS:
                key = hisKey.hex()
                xored = bytes(b ^ ord(key[i % len(key)]) for i, b in enumerate(line.encode('utf-8')))
                return base64.b64encode(xored)
            try:
                from ctypes import c_uint8, POINTER, byref, c_size_t
                data = line.encode('utf-8')
                key = (c_uint8 * 32)(*hisKey)
                ptArray = (c_uint8 * len(data))(*data)
                encrypted = CryptoMessage()

                if cryptoLib.cryptoEncryptMessage(ptArray, len(data), key, byref(encrypted)) != 0:
                    return None

                ctBytes = bytes(encrypted.ciphertext[:encrypted.ciphertextLen])
                nonceBytes = bytes(encrypted.nonce)
                tagBytes = bytes(encrypted.tag)

                cryptoLib.cryptoFreeMessage(byref(encrypted))

                return ctBytes + nonceBytes + tagBytes
            except:
                return None

        def decryptLine(encData):
            if not encData:
                return ""

            if not USE_C_LIBS:
                # Fallback XOR
                try:
                    raw = base64.b64decode(encData)
                    key = hisKey.hex()
                    data = bytes(b ^ ord(key[i % len(key)]) for i, b in enumerate(raw))
                    return data.decode('utf-8')
                except:
                    return ""

            try:
                from ctypes import c_uint8, POINTER, byref, c_size_t

                if len(encData) < 28:
                    return ""

                ctLen = len(encData) - 28
                key = (c_uint8 * 32)(*hisKey)

                encrypted = CryptoMessage()
                encrypted.ciphertext = (c_uint8 * ctLen)(*encData[:ctLen])
                encrypted.ciphertextLen = ctLen
                encrypted.nonce = (c_uint8 * 12)(*encData[ctLen:ctLen+12])
                encrypted.tag = (c_uint8 * 16)(*encData[ctLen+12:ctLen+28])

                plaintext = POINTER(c_uint8)()
                ptLen = c_size_t()

                if cryptoLib.cryptoDecryptMessage(byref(encrypted), key, byref(plaintext), byref(ptLen)) != 0:
                    return ""

                data = bytes(plaintext[:ptLen.value]).decode('utf-8')
                return data
            except:
                return ""

        def preInputHook():
            histLen = readline.get_current_history_length()
            if histLen > 0:
                idx = histLen - 1
                if idx < len(encHistory):
                    decrypted = decryptLine(encHistory[idx])
                    if decrypted:
                        readline.replace_history_item(idx, decrypted)

        def secureWipe():
            nonlocal hisKey
            hisKey = bytearray(os.urandom(32))

            for i in range(len(encHistory)):
                encHistory[i] = os.urandom(len(encHistory[i]))

            encHistory.clear()

            readline.clear_history()

        atexit.register(secureWipe)

        def signalHandler(sig, frame):
            secureWipe()
            sys.exit(0)

        signal.signal(signal.SIGINT, signalHandler)
        signal.signal(signal.SIGTERM, signalHandler)


        readline.set_history_length(100)
        readline.set_pre_input_hook(preInputHook)


        def completer(text, state):
            cmds = [
                '/peers', '/who', '/fingerprint', '/verify', '/xor', '/chacha',
                '/me', '/block', '/unblock', '/known', '/ping', '/stats',
                '/clear', '/cleam', '/gip', '/sip', '/help', '/quit'
            ]
            matches = [c for c in cmds if c.startswith(text)]
            return matches[state] if state < len(matches) else None

        readline.set_completer(completer)
        readline.parse_and_bind('tab: complete')

        try:
            while self.running:
                try:
                    with self.peersLock:
                        active = len([p for p in self.peers.values() if p['connected']])

                    prompt = f"{Sex.GRAY}{Sex.END}{Sex.PURPLE}>{Sex.END} "
                    text = input(prompt)

                    if not text.strip():
                        continue

                    encrypted = encryptLine(text)
                    if encrypted:
                        encHistory.append(encrypted)
                        readline.add_history(text)

                    if text.startswith('/'):
                        self.processCmd(text)
                    else:
                        self.sendChatMessage(text)

                except EOFError:
                    break
                except KeyboardInterrupt:
                    print("\n")
                    break
        finally:
            secureWipe()
            self.stop()


    def detectFormat(self, text: str) -> str:
        if text.startswith('\\x'):
            return 'hex'

        if len(text) % 4 != 0:
            return 'plain'

        try:
            decoded = base64.b64decode(text, validate=True)
            if decoded:
                return 'base64'
        except:
            pass

        return 'plain'


    def cmdXor(self, text, password, decode=False):
        fmt = self.detectFormat(text)

        try:
            if fmt != 'plain':
                # DECODE
                if fmt == 'hex':
                    hexStr = text.replace('\\x', '')
                    raw = bytes.fromhex(hexStr).decode('latin1')
                else:  # base64
                    raw = base64.b64decode(text.encode()).decode('latin1')

                result = self.xorCipher(raw, password)

                print(f"\n{Sex.CYAN}[decoded XOR]{Sex.END}")
                print(f"{Sex.PURPLE}{result}{Sex.END}\n")

            else:
                # ENCODE
                xored = self.xorCipher(text, password)
                b64 = base64.b64encode(xored.encode('latin1')).decode()
                hexRep = ''.join(f'\\x{ord(c):02x}' for c in xored)

                print(f"\n{Sex.CYAN}[encoded XOR]{Sex.END}")
                print(f"{Sex.GRAY}base64  ::{Sex.END} {Sex.PURPLE}{b64}{Sex.END}")
                print(f"{Sex.GRAY}hex     ::{Sex.END} {Sex.PURPLE}{hexRep}{Sex.END}\n")

        except Exception as e:
            print(f"{Sex.B_RED}[ERR] XOR failed :: {e}{Sex.END}")


    def cmdChacha(self, text, password, decode=False):
        if not USE_C_LIBS:
            print(f"{Sex.B_RED}[ERR] Chacha use modules libs{Sex.END}")
            return

        oldKey = self.xorKey
        try:
            self.xorKey = password
            fmt = self.detectFormat(text)

            if fmt != 'plain':
                # DECODE
                if fmt == 'hex':
                    hexStr = text.replace('\\x', '')
                    combined = bytes.fromhex(hexStr)
                    text = base64.b64encode(combined).decode()

                result = self.decryptMessages(text)

                print(f"\n{Sex.CYAN}[decoded Chacha20-Poly1305]{Sex.END}")
                print(f"{Sex.PURPLE}{result}{Sex.END}\n")

            else:
                # ENCODE
                encoded = self.encryptMessage(text)
                combined = base64.b64decode(encoded.encode())

                hexRep = ''.join(f'\\x{b:02x}' for b in combined)

                print(f"\n{Sex.CYAN}[encoded Chacha20-Poly1305]{Sex.END}")
                print(f"{Sex.GRAY}base64  ::{Sex.END} {Sex.PURPLE}{encoded}{Sex.END}")
                print(f"{Sex.GRAY}hex     ::{Sex.END} {Sex.PURPLE}{hexRep}{Sex.END}\n")


        except Exception as e:
            print(f"{Sex.B_RED}[ERR] Chacha failed  ::  {e}{Sex.END}")
        finally:
            self.xorKey = oldKey


    def isBase64(self, s:str) -> bool:
        try:
            base64.b64decode(s, validate=True)
            return True
        except:
            return False

    def processCmd(self, cmd):
        rawCmd = cmd.strip()
        cmd = rawCmd.lower()


        if cmd == '/peers':
            with self.peersLock:
                activePeers = [(addr, p) for addr, p in self.peers.items() if p['connected']]

            if activePeers:
                print(f"\n{Sex.PURPLE}connected peers ({len(activePeers)}){Sex.END}")
                for addr, peer in activePeers:
                    print(f"{Sex.GRAY}  • {peer['username']} @ {addr}{Sex.END}")
                print(f"\n{Sex.GRAY}known peers :: {len(self.knownPeers)}{Sex.END}\n")
            else:
                print(f"{Sex.GRAY}[no peers connected]{Sex.END}\n")

        elif cmd == '/fingerprint':
            if self.myFingerprint:
                print(f"\n{Sex.PURPLE}{self.myFingerprint}{Sex.END}")
            else:
                print(f"{Sex.GRAY}[FINGERPRINT]  ::{Sex.END} {Sex.CYAN}DISABLED{Sex.END}")

        elif cmd == '/verify':
            print(f"{Sex.GRAY}[err] usage ::{Sex.END} {Sex.CYAN}/verify <username> <fingerprint>{Sex.END}")
        elif cmd.startswith('/verify '):
            parts = cmd.split()
            if len(parts) < 6:
                print(f"{Sex.GRAY}[err] usage ::{Sex.END} {Sex.CYAN}/verify <username> <fingerprint>{Sex.END}")
                return
            username = parts[1]
            fingerprint = ' '.join(parts[2:6]).upper()

            self.trustedFingerprints[username] = fingerprint
            print(f"{Sex.PURPLE}[VERIFIED]{Sex.END} {Sex.CYAN}{username} :: {fingerprint}{Sex.END}")

            with self.peersLock:
                for addr, peer in self.peers.items():
                    if peer['username'] == username:
                        self.sendMsg(peer['conn'], {'type': 'fingerprint_request'})



        elif cmd == "/who":
            users = set()
            with self.peersLock:
                for p in self.peers.values():
                    if p['connected']:
                        users.add(p['username'])
            users.add(self.username)

            print(f"\n{Sex.GRAY}  [Users]{Sex.END}")
            for u in sorted(users):
                print(f"  {Sex.PURPLE}{u}{Sex.END}")
            print("")

        elif cmd == '/xor':
            print(f"{Sex.GRAY}[err] usage ::{Sex.END} {Sex.CYAN}/xor <textBubby's> -p ;; --password <password>{Sex.END}")
        elif cmd.startswith('/xor '):
            parts = rawCmd.split(maxsplit=1)[1]

            decode = '-d' in parts or '--decode' in parts
            parts = parts.replace('-d', '').replace('--decode', '').strip()

            if '-p' in parts:
                pFlag = '-p'
            elif '--password' in parts:
                pFlag = '--password'
            else:
            #if '-p' not in parts and '--password' not in parts:
                print(f"{Sex.B_RED}[err] missing password{Sex.END}")
                print(f"{Sex.GRAY}usage  ::{Sex.END}  {Sex.CYAN}/xor <textBubby's> -p :: --password <myfuckPassword>{Sex.END}")
                return
            try:
                pIdx = parts.index(pFlag)
                text = parts[:pIdx].strip()
                password = parts[pIdx + len(pFlag):].strip().split(maxsplit=1)[0]

                if not text:
                        print(f"{Sex.B_RED}[err] Missing text{Sex.END}")
                        return
                self.cmdXor(text, password, decode)
            except Exception:
                print(f"{Sex.B_RED}[err] invalid format{Sex.END}")
                print(f"{Sex.GRAY}[err] usage ::{Sex.END} {Sex.CYAN}/xor <textBubby's> -p ;; --password <password>{Sex.END}")


        elif cmd == '/chacha':
            print(f"{Sex.GRAY}[err] usage ::{Sex.END} {Sex.CYAN}/chacha <textBubby's> -p ;; --password <password>{Sex.END}")
        elif cmd.startswith('/chacha '):
            parts = rawCmd.split(maxsplit=1)[1]

            decode = '-d' in parts or '--decode' in parts
            parts = parts.replace('-d', '').replace('--decode', '').strip()

            if '-p' not in parts and '--password' not in parts:
                print(f"{Sex.B_RED}[err] missing password{Sex.END}")
                print(f"{Sex.GRAY}usage  ::{Sex.END}  {Sex.CYAN}/chacha <textBubby's> -p :: --password <myfuckPassword>{Sex.END}")
            else:
                try:
                    if '-p' in parts:
                        pIdx = parts.index('-p')
                        pFlag = '-p'
                    else:
                        pIdx = parts.index('--password')
                        pFlag = '--password'

                    beforeP = parts[:pIdx].strip()
                    afterP = parts[pIdx + len(pFlag):].strip().split(maxsplit=1)

                    if not afterP:
                        print(f"{Sex.B_RED}[err] Missing password{Sex.END}")
                    else:
                        password = afterP[0]
                        text = beforeP

                        if not text:
                            print(f"{Sex.B_RED}[err] Missing text{Sex.END}")
                        else:
                            self.cmdChacha(text, password, decode)
                except Exception:
                    print(f"{Sex.B_RED}[err] invalid format{Sex.END}")
                    print(f"{Sex.GRAY}[err] usage ::{Sex.END} {Sex.CYAN}/chacha <textBubby's> -p ;; --password <password>{Sex.END}")

        elif cmd == '/me':
            print(f"{Sex.GRAY}[err] usage ::{Sex.END} {Sex.CYAN}/me <action>{Sex.END}")
        elif cmd.startswith('/me '):
            action = cmd.split(maxsplit=1)[1].strip()

            if not action:
                print(f"{Sex.B_RED}[err]{Sex.END} usage :: /me <action>")
                return
            self.sendChatMessage(f"   {Sex.N_RED}[{self.username}]{Sex.END} {Sex.PURPLE}{action}{Sex.CYAN}")

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

        elif cmd == "/known":
            print(f"\n  [known peers] :: {Sex.CYAN}{datetime.now().date()}{Sex.END}")
            for p in sorted(self.knownPeers):
                print(f"  {p}")
            print("")

        elif cmd == "/ping":
            with self.peersLock:
                for addr, p in self.peers.items():
                    if p['connected']:
                        delta = int(time.time() - p['lastSeen'])
                        print(f"{Sex.GRAY}{addr} ::{Sex.END} {Sex.CYAN}last seen{Sex.END} {Sex.B_RED}{delta}s{Sex.END} {Sex.CYAN}ago{Sex.END}")

        elif cmd == "/stats":
            uptime = int(time.time() - self.startTime)

            with self.peersLock:
                active = len([p for p in self.peers.values() if p['connected']])
            print(f"""
{Sex.GRAY}[stats]  :: [param]{Sex.END}
{Sex.WHITE}uptime    ::{Sex.END}  {Sex.PURPLE}{uptime}s{Sex.END}
{Sex.WHITE}peers     ::{Sex.END}  {Sex.PURPLE}{active}{Sex.END}
{Sex.WHITE}known     ::{Sex.END}  {Sex.PURPLE}{len(self.knownPeers)}{Sex.END}
{Sex.WHITE}msgs      ::{Sex.END}  {Sex.PURPLE}{len(self.messageHistory)}{Sex.END}
{Sex.WHITE}muted     ::{Sex.END}  {Sex.PURPLE}{len(self.blockedUsers)}{Sex.END}
{Sex.WHITE}stealth   ::{Sex.END}  {Sex.CYAN if self.stealthMode else Sex.GRAY}{'ON' if self.stealthMode else 'OFF'}{Sex.END}
{Sex.WHITE}paran     ::{Sex.END}  {Sex.CYAN if self.paranMode else Sex.GRAY}{'ON (' + str(self.paranDelay) + 's)' if self.paranMode else 'OFF'}{Sex.END}
{Sex.WHITE}obfuscate ::{Sex.END}  {Sex.CYAN if self.obfuscateMode else Sex.GRAY}{'ON' if self.obfuscateMode else 'OFF'}{Sex.END}
{Sex.WHITE}ratelimit ::{Sex.END}  {Sex.CYAN if self.rateLimitMax > 0 else Sex.GRAY}{str(self.rateLimitMax) + '/min' if self.rateLimitMax > 0 else 'OFF'}{Sex.END}
                  """)
            if self.mediaEnabled:
                print(f"{Sex.WHITE}drops     ::{Sex.END}  {Sex.PURPLE}{len(self.dropTransfers)}{Sex.END}")


        elif cmd in ['/cls', 'clear', 'clean']:
            self.cleanScreen()
            self.cleanMem()
            print(f"{Sex.GRAY}[Cleaned]{Sex.END}\n")

        elif cmd == '/cleam':
            self.cleanScreen()
            self.cleanMem()

            #self.knownPeers.clear()
            #self.seenMessages.clear()
            #self.messageHistory.clear()

            with self.knownPeersLock:
                self.knownPeers.clear()
                if self.myOnion:
                    self.knownPeers.add(f"{self.myOnion}:{self.port}")

            print(f"{Sex.GRAY}[full clean memory and logs excuted!]{Sex.END}\n")

        elif cmd == '/geo':
            print(f"{Sex.GRAY}[err] usage  ::{Sex.END}  {Sex.CYAN}/geo <ip>{Sex.END}")

        elif cmd.startswith('/geo '):
            args = cmd.split()[1:]

            result = geo.run(args)

            if "err" in result:
                print(f"{Sex.B_RED}[err] {result['err']}{Sex.END}")
                return
            print(f"{Sex.PURPLE}[results by consulta]{Sex.END}")
            for k, v in result.items():
                print(f"{Sex.GRAY}{k:<10}{Sex.END} :: {Sex.CYAN}{v}{Sex.END}")
            print("")

        elif cmd == '/sip':
            print(f"{Sex.GRAY}[err] usage  ::{Sex.END}  {Sex.CYAN}/sip <ip>{Sex.END}")

        elif cmd.startswith('/sip '):
            parts = cmd.split()
            if len(parts) < 2:
                print("[err]")
                return
            ip = parts[1]
            print("[scanning]")
            results = sip.scanIp(ip, (1, 2200))
            out = sip.formatOut(ip, results)
            print(out)



        elif cmd in ['h', 'm', 'menu', 'help', 'ayuda']:
            print(f"\n{Sex.GRAY}[commands]       [desc]{Sex.END}")
            print(f"  /peers     {Sex.GRAY}::{Sex.END} {Sex.CYAN}show peers{Sex.END}")
            print(f"  /known     {Sex.GRAY}::{Sex.END} {Sex.CYAN}show known Peers{Sex.END}")
            print(f"  /who       {Sex.GRAY}::{Sex.END} {Sex.CYAN}show all users online{Sex.END}")
            print(f"  /ping      {Sex.GRAY}::{Sex.END} {Sex.CYAN}ping peer address time{Sex.END}")
            print(f"  /me        {Sex.GRAY}::{Sex.END} {Sex.CYAN}actions text user{Sex.END}")
            print(f"  /to        {Sex.GRAY}::{Sex.END} {Sex.CYAN}send private message{Sex.END}")
            print(f"  /clear     {Sex.GRAY}::{Sex.END} {Sex.CYAN}clean screen and memory{Sex.END}")
            print(f"  /cleam     {Sex.GRAY}::{Sex.END} {Sex.CYAN}clean full logs and memory{Sex.END}")
            print(f"  /block     {Sex.GRAY}::{Sex.END} {Sex.CYAN}block and mute user{Sex.END}")
            print(f"  /unblock   {Sex.GRAY}::{Sex.END} {Sex.CYAN}unblock and unmute user{Sex.END}")
            print(f"  /stats     {Sex.GRAY}::{Sex.END} {Sex.CYAN}stats room{Sex.END}")
            print(f"  /xor       {Sex.GRAY}::{Sex.END} {Sex.CYAN}encode | decode :: using xor{Sex.END}")
            print(f"  /chacha    {Sex.GRAY}::{Sex.END} {Sex.CYAN}decode | decode :: using Chacha20-Poly1305{Sex.END}")
            print(f"  /b64       {Sex.GRAY}::{Sex.END} {Sex.CYAN}encode | decode :: using base64{Sex.END}")
            print(f"  /encode    {Sex.GRAY}::{Sex.END} {Sex.CYAN}encode (url|hex|rot13){Sex.END}")
            print(f"  /decode    {Sex.GRAY}::{Sex.END} {Sex.CYAN}decode (url|hex|rot13){Sex.END}")
            print(f"  /hash      {Sex.GRAY}::{Sex.END} {Sex.CYAN}hash text with SHA256 :: MD5{Sex.END}")
            print(f"  /verify    {Sex.GRAY}::{Sex.END} {Sex.CYAN}verify fingerprint user{Sex.END}")
            print(f"  /export    {Sex.GRAY}::{Sex.END} {Sex.CYAN}Export chat history{Sex.END}")
            print(f"\n{Sex.GRAY} [Tools]         [desc]{Sex.END}")
            print(f"  /geo       {Sex.GRAY}::{Sex.END} {Sex.CYAN}geo localize ip public{Sex.END}")
            print(f"  /geo2      {Sex.GRAY}::{Sex.END} {Sex.CYAN}IP geolocation (extensive){Sex.END}")
            print(f"  /whois     {Sex.GRAY}::{Sex.END} {Sex.CYAN}WHOIS lookup (domain|IP){Sex.END}")
            print(f"  /genip     {Sex.GRAY}::{Sex.END} {Sex.CYAN}IP generator{Sex.END}")
            print(f"  /ip        {Sex.GRAY}::{Sex.END} {Sex.CYAN}IP research extensive{Sex.END}")
            print(f"  /ua        {Sex.GRAY}::{Sex.END} {Sex.CYAN}user-Agent :: payloads generator{Sex.END}")
            print(f"  /pastebin  {Sex.GRAY}::{Sex.END} {Sex.CYAN}upload file by paste.rs{Sex.END}")

            #print(f"  /sip       {Sex.GRAY}::{Sex.END} {Sex.CYAN}scann ports to ip{Sex.END}")
            if self.mediaEnabled:
                print(f"\n{Sex.GRAY} [Media]         [desc]{Sex.END}")
                print(f"  /send      {Sex.GRAY}::{Sex.END} {Sex.CYAN}send file to user{Sex.END}")
                print(f"  /drop      {Sex.GRAY}::{Sex.END} {Sex.CYAN}send temporary file{Sex.END}")
                print(f"  /drops     {Sex.GRAY}::{Sex.END} {Sex.CYAN}list drops availables{Sex.END}")
                print(f"  /share     {Sex.GRAY}::{Sex.END} {Sex.CYAN}share folder (zipped){Sex.END}")
                print(f"  /accept    {Sex.GRAY}::{Sex.END} {Sex.CYAN}accept file transfer{Sex.END}")
                print(f"  /reject    {Sex.GRAY}::{Sex.END} {Sex.CYAN}reject file transfer{Sex.END}")
                print(f"  /transfers {Sex.GRAY}::{Sex.END} {Sex.CYAN}show active transfers{Sex.END}")

            if self.relayMode:
                print(f"\n{Sex.GRAY} [Relay]         [desc]{Sex.END}")
                print(f"  /relay     {Sex.GRAY}::{Sex.END} {Sex.CYAN}show relay stats{Sex.END}")


            print(f"\n  /quit      {Sex.GRAY}::{Sex.END} {Sex.CYAN}exit room{Sex.END}\n")

        elif cmd == '/send':
            if not self.mediaEnabled:
                print(f"{Sex.B_RED}[err] Media mode not enabled. Use -M flag{Sex.END}")
                return
            print(f"{Sex.GRAY}[err] usage ::{Sex.END} {Sex.CYAN}/send <file> <username>{Sex.END}")

        elif cmd.startswith('/send '):
            if not self.mediaEnabled:
                print(f"{Sex.B_RED}[err] Media mode not enabled{Sex.END}")
                return

            parts = rawCmd.split(maxsplit=2)
            if len(parts) < 3:
                print(f"{Sex.GRAY}[err] usage ::{Sex.END} {Sex.CYAN}/send <file> <username>{Sex.END}")
                return

            filepath = parts[1]
            targetPeer = parts[2]

            self.sendFile(filepath, targetPeer)

        elif cmd == '/share':
            if not self.mediaEnabled:
                print(f"{Sex.B_RED}[err] Media mode not enabled. Use -M flag{Sex.END}")
                return
            print(f"{Sex.GRAY}[err] usage ::{Sex.END} {Sex.CYAN}/share <folder> <username>{Sex.END}")

        elif cmd.startswith('/share '):
            if not self.mediaEnabled:
                print(f"{Sex.B_RED}[err] Media mode not enabled{Sex.END}")
                return

            parts = rawCmd.split(maxsplit=2)
            if len(parts) < 3:
                print(f"{Sex.GRAY}[err] usage ::{Sex.END} {Sex.CYAN}/share <folder> <username>{Sex.END}")
                return

            folderpath = parts[1]
            targetPeer = parts[2]

            self.sendFolder(folderpath, targetPeer)

        elif cmd == '/accept':
            if not self.mediaEnabled:
                print(f"{Sex.B_RED}[err] Media mode not enabled{Sex.END}")
                return
            print(f"{Sex.GRAY}[err] usage ::{Sex.END} {Sex.CYAN}/accept <transfer_id>{Sex.END}")

        elif cmd.startswith('/accept '):
            if not self.mediaEnabled:
                print(f"{Sex.B_RED}[err] Media mode not enabled{Sex.END}")
                return

            transferId = cmd.split()[1] if len(cmd.split()) > 1 else None

            if not transferId:
                print(f"{Sex.GRAY}[err] usage ::{Sex.END} {Sex.CYAN}/accept <transfer_id>{Sex.END}")
                return

            self.acceptTransfer(transferId)

        elif cmd == '/reject':
            if not self.mediaEnabled:
                print(f"{Sex.B_RED}[err] Media mode not enabled{Sex.END}")
                return
            print(f"{Sex.GRAY}[err] usage ::{Sex.END} {Sex.CYAN}/reject <transfer_id>{Sex.END}")

        elif cmd.startswith('/reject '):
            if not self.mediaEnabled:
                print(f"{Sex.B_RED}[err] Media mode not enabled{Sex.END}")
                return

            transferId = cmd.split()[1] if len(cmd.split()) > 1 else None

            if not transferId:
                print(f"{Sex.GRAY}[err] usage ::{Sex.END} {Sex.CYAN}/reject <transfer_id>{Sex.END}")
                return

            self.rejectTransfer(transferId)

        elif cmd == '/transfers':
            if not self.mediaEnabled:
                print(f"{Sex.B_RED}[err] Media mode not enabled{Sex.END}")
                return

            if not self.pendingTransfers and not self.mediaTransfer:
                print(f"{Sex.GRAY}[Media] No active transfers{Sex.END}")
                return

            if self.pendingTransfers:
                print(f"\n{Sex.CYAN}[Pending Transfers]{Sex.END}")
                for tid, t in self.pendingTransfers.items():
                    print(f"{Sex.GRAY}  {tid[:8]}... :: {t['filename']} from {t['from']} ({self.formatSize(t['filesize'])}){Sex.END}")

            if self.mediaTransfer:
                print(f"\n{Sex.CYAN}[Active Transfers]{Sex.END}")
                for tid, t in self.mediaTransfer.items():
                    status = t.get('status', 'unknown')
                    if 'sent' in t:
                        progress = (t['sent'] / t['filesize']) * 100
                        print(f"{Sex.GRAY}  {tid[:8]}... :: {status} {progress:.1f}%{Sex.END}")
                    else:
                        progress = (t.get('received', 0) / t['filesize']) * 100
                        print(f"{Sex.GRAY}  {tid[:8]}... :: {status} {progress:.1f}%{Sex.END}")
            print()

        elif cmd == '/relay':
            if not self.relayMode:
                print(f"{Sex.B_RED}[err] Relay mode not enabled. Use -R flag{Sex.END}")
                return

            print(f"\n{Sex.CYAN}[Relay Statistics]{Sex.END}")
            print(f"{Sex.GRAY}  Messages relayed: {Sex.WHITE}{self.relayStats['messages']}{Sex.END}")
            print(f"{Sex.GRAY}  Bytes transferred: {Sex.WHITE}{self.formatSize(self.relayStats['bytes'])}{Sex.END}")
            print(f"{Sex.GRAY}  Unique peers: {Sex.WHITE}{len(self.relayStats['peers'])}{Sex.END}\n")


        elif cmd == '/drop':
            if not self.mediaEnabled:
                print(f"{Sex.B_RED}[err] Media mode not enabled{Sex.END}")
                return
            print(f"{Sex.GRAY}[err] usage ::{Sex.END} {Sex.CYAN}/drop <file|folder> <username> [-t|--time <seconds>]{Sex.END}")

        elif cmd.startswith('/drop '):
            if not self.mediaEnabled:
                print(f"{Sex.B_RED}[err] Media mode not enabled{Sex.END}")
                return
                
            args = rawCmd[6:].strip()

            timeLimit = 60
            if ' -t ' in args or ' --time ' in args:
                if ' -t ' in args:
                    parts = args.split(' -t ')
                    flag = '-t'
                else:
                    parts = args.split(' --time ')
                    flag = '--time'
                    
                if len(parts) == 2:
                    pathAndUser = parts[0].strip().rsplit(None, 1)
                    if len(pathAndUser) == 2:
                        filepath = pathAndUser[0]
                        targetPeer = pathAndUser[1]
                        try:
                            timeLimit = int(parts[1].strip().split()[0])
                        except:
                            print(f"{Sex.B_RED}[err] Invalid time value{Sex.END}")
                            return
                    else:
                        print(f"{Sex.GRAY}[err] usage ::{Sex.END} {Sex.CYAN}/drop <file|folder> <username> [-t|--time <seconds>]{Sex.END}")
                        return
                else:
                    print(f"{Sex.GRAY}[err] usage ::{Sex.END} {Sex.CYAN}/drop <file|folder> <username> [-t|--time <seconds>]{Sex.END}")
                    return
            else:
                pathAndUser = args.rsplit(None, 1)
                if len(pathAndUser) == 2:
                    filepath = pathAndUser[0]
                    targetPeer = pathAndUser[1]
                else:
                    print(f"{Sex.GRAY}[err] usage ::{Sex.END} {Sex.CYAN}/drop <file|folder> <username> [-t|--time <seconds>]{Sex.END}")
                    return
                    
            self.sendDrop(filepath, targetPeer, timeLimit)


        elif cmd == '/drops':
            if self.dropTransfers:
                print(f"{Sex.CYAN} [active drops]   [name]    [time]{Sex.END}")
                for tid, drop in self.dropTransfers.items():
                    rem = int(drop['deadline'] - time.time())
                    print(f"{Sex.GRAY}  {tid[:8]}xxxx :: {drop.get('filename')} [{rem}s left]{Sex.END}")
            else:
                print(f"{Sex.GRAY} [Not drops availables]{Sex.END}{Sex.CYAN} {datetime.now().date()}{Sex.END}")

        elif cmd == '/to':
            print(f"{Sex.GRAY}[err] usage ::{Sex.END} {Sex.CYAN}/to <username> <message>{Sex.END}")
            
        elif cmd.startswith('/to '):
            parts = rawCmd.split(maxsplit=2)
            if len(parts) < 3:
                print(f"{Sex.GRAY}[err] usage ::{Sex.END} {Sex.CYAN}/to <username> <message>{Sex.END}")
                return
                
            targetUser = parts[1]
            message = parts[2]
            
            if targetUser == self.username:
                print(f"{Sex.B_RED}[err] Cannot send private message to yourself{Sex.END}")
                return
                
            self.sendPrivateMessage(targetUser, message)


        elif cmd == '/b64':
            print(f"{Sex.GRAY}[err] usage ::{Sex.END} {Sex.CYAN}/b64 <text>{Sex.END}")
            
        elif cmd.startswith('/b64 '):
            import re
            fullText = rawCmd[5:]
            cleanText = re.sub(r'\s+-[a-z]\s+\S+$', '', fullText)  # Quita " -p xxx"
            cleanText = re.sub(r'\s+--[a-z]+\s+\S+$', '', cleanText)  # Quita " --password xxx"
            cleanText = cleanText.strip()
            
            if not cleanText:
                print(f"{Sex.B_RED}[err] Missing text{Sex.END}")
                return
                
            try:
                try:
                    decoded = base64.b64decode(cleanText, validate=True).decode('utf-8')
                    print(f"\n{Sex.CYAN}[decoded base64]{Sex.END}")
                    print(f"{Sex.PURPLE}{decoded}{Sex.END}\n")
                except:
                    encoded = base64.b64encode(cleanText.encode('utf-8')).decode('utf-8')
                    print(f"\n{Sex.CYAN}[encoded base64]{Sex.END}")
                    print(f"{Sex.PURPLE}{encoded}{Sex.END}\n")
                    
            except Exception as e:
                print(f"{Sex.B_RED}[ERR] base64 failed :: {e}{Sex.END}")



        elif cmd == '/hash':
            print(f"{Sex.GRAY}[err] usage ::{Sex.END} {Sex.CYAN}/hash <text> [-a|--algo sha256|md5]{Sex.END}")
            
        elif cmd.startswith('/hash '):
            args = rawCmd[6:].strip()
            
            algo = 'sha256'  # def
            if ' -a ' in args or ' --algo ' in args:
                if ' -a ' in args:
                    parts = args.split(' -a ')
                else:
                    parts = args.split(' --algo ')
                    
                if len(parts) == 2:
                    text = parts[0].strip()
                    algoInput = parts[1].strip().lower()
                    if algoInput in ['sha256', 'md5']:
                        algo = algoInput
                    else:
                        print(f"{Sex.B_RED}[err] Invalid algorithm. Use: sha256 or md5{Sex.END}")
                        return
                else:
                    text = args
            else:
                text = args
                
            if not text:
                print(f"{Sex.B_RED}[err] Missing text{Sex.END}")
                return
                
            try:
                isHash = False
                if algo == 'sha256' and len(text) == 64 and all(c in '0123456789abcdefABCDEF' for c in text):
                    isHash = True
                    print(f"\n{Sex.CYAN}[SHA256 Hash detected]{Sex.END}")
                    print(f"{Sex.GRAY}Hash ::{Sex.END} {Sex.PURPLE}{text.lower()}{Sex.END}")
                    print(f"{Sex.N_RED}[Cannot reverse hash :: [one-way func]]{Sex.END}\n")
                elif algo == 'md5' and len(text) == 32 and all(c in '0123456789abcdefABCDEF' for c in text):
                    isHash = True
                    print(f"\n{Sex.CYAN}[MD5 Hash detected]{Sex.END}")
                    print(f"{Sex.GRAY}Hash ::{Sex.END} {Sex.PURPLE}{text.lower()}{Sex.END}")
                    print(f"{Sex.N_RED}[Cannot reverse hash :: [one-way func]]{Sex.END}\n")
                else:
                    # Encode
                    if algo == 'sha256':
                        hashed = hashlib.sha256(text.encode('utf-8')).hexdigest()
                        print(f"\n{Sex.CYAN}[SHA256 Hash]{Sex.END}")
                    else:  # md5
                        hashed = hashlib.md5(text.encode('utf-8')).hexdigest()
                        print(f"\n{Sex.CYAN}[MD5 Hash]{Sex.END}")
                        
                    print(f"{Sex.GRAY}Input ::{Sex.END} {Sex.WHITE}{text}{Sex.END}")
                    print(f"{Sex.GRAY}Hash  ::{Sex.END} {Sex.PURPLE}{hashed}{Sex.END}\n")
                    
            except Exception as e:
                print(f"{Sex.B_RED}[ERR] Hash failed :: {e}{Sex.END}")

        elif cmd == '/export':
            filename = f"chatHistory-{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(filename, 'w') as f:
                for msg in self.messageHistory:
                    f.write(f"[{msg.get('timestamp')}] {msg.get('username')}: {msg.get('message')}\n")
                print(f"{Sex.PURPLE}[exported to {filename}]{Sex.END}")
        
        elif cmd == '/whois':
            print(f"{Sex.GRAY}[err] usage ::{Sex.END} {Sex.CYAN}/whois <dominio|ip>{Sex.END}")

        elif cmd.startswith('/whois '):
            target = cmd.split()[1]

            import subprocess
            try:
                out = subprocess.check_output(
                    ["whois", target],
                    stderr=subprocess.STDOUT,
                    text=True
                )
                print(f"{Sex.CYAN}         [whois sys]{Sex.END}")
                print(out)
            except Exception as e:
                print(f"{Sex.B_RED}[err] {e}{Sex.END}")

        elif cmd == '/pastebin':
            print(f"{Sex.GRAY}[err] usage ::{Sex.END} {Sex.CYAN}/pastebin <~/path/to/filx>{Sex.END}")

        elif cmd.startswith('/pastebin '):
            filepath = rawCmd.split(maxsplit=1)[1]

            try:
                with open(filepath, 'r') as f:
                    content = f.read()

                import requests
                r = requests.post('https://paste.rs/', data=content)

                if r.status_code == 200:
                    url = r.text.strip()
                    print(f"{Sex.CYAN}[uploaded]{Sex.END} -> {Sex.PURPLE}{url}{Sex.END}")
                    try:
                        import pyperclip
                        pyperclip.copy(url)
                        print(f"{Sex.GRAY}[url copied in clipboard]{Sex.END}")
                    except:
                        pass
                else:
                    print(f"{Sex.B_RED}[upload failed]{Sex.END}")
            except Exception as e:
                print(f"{Sex.B_RED}[err] :: {e}{Sex.END}")

        elif cmd == '/encode':
            print(f"{Sex.GRAY}[err] usage ::{Sex.END} {Sex.CYAN}/encode [url|hex|rot13] <text>{Sex.END}")
        
        elif cmd.startswith('/encode '):
            args = rawCmd.split(maxsplit=2)
            if len(args) < 3:
                print(f"{Sex.GRAY}[err] usage ::{Sex.END} {Sex.CYAN}/encode [url|hex|rot12] <text>{Sex.END}")
                return
            
            enctype = args[1].lower()
            text = args[2]

            if enctype == 'url':
                import urllib.parse
                encode = urllib.parse.quote(text)
            elif enctype == 'hex':
                encode = text.encode().hex()
            elif enctype == 'rot13':
                import codecs
                encode = codecs.encode(text, 'rot13')
            else:
                print(f"{Sex.B_RED}[unknown encode type] :: [url|hex|rot13]{Sex.END}")
                return

            print(f"\n{Sex.CYAN}[{enctype.upper()}]{Sex.END}")
            print(f"{Sex.GRAY}[origin]  ::{Sex.END} {text}")
            print(f"{Sex.GRAY}[encode]  ::{Sex.END} {Sex.PURPLE}{encode}{Sex.END}")

        elif cmd == '/decode':
            print(f"{Sex.GRAY}[err] usage ::{Sex.END} {Sex.CYAN}/decode [url|hex|rot12] <encoded>{Sex.END}")

        elif cmd.startswith('/decode '):
            args = rawCmd.split(maxsplit=2)
            if len(args) < 3:
                print(f"{Sex.GRAY}Usage: /decode [url|hex|rot13] <text>{Sex.END}")
                return

            decType = args[1].lower()
            text = args[2]

            try:
                if decType == 'url':
                    import urllib.parse
                    decoded = urllib.parse.unquote(text)

                elif decType == 'hex':
                    decoded = bytes.fromhex(text).decode()

                elif decType == 'rot13':
                    import codecs
                    decoded = codecs.decode(text, 'rot13')

                else:
                    print(f"{Sex.B_RED}unknown decoding{Sex.END}")
                    return

                print(f"\n{Sex.CYAN}[{decType.upper()}]{Sex.END}")
                print(f"{Sex.GRAY}Encoded  ::{Sex.END} {text}")
                print(f"{Sex.GRAY}Decoded  ::{Sex.END} {Sex.PURPLE}{decoded}{Sex.END}\n")

            except Exception as e:
                print(f"{Sex.B_RED}[err] {e}{Sex.END}")

        elif cmd == '/genip':
            print(f"{Sex.GRAY}[err] usage ::{Sex.END} {Sex.CYAN}/genip <args>{Sex.END}")
        elif cmd.startswith('/genip '):
            args = rawCmd.split(maxsplit=1)[1]

            import subprocess

            try:
                proc = subprocess.run(
                    ["python3", "python/tools/genip.py"] + args.split(),
                    text=True,
                    capture_output=True
                )

                if proc.returncode == 0:
                    print(f"{Sex.CYAN}[GIp]{Sex.END}")
                    print(proc.stdout)
                else:
                    print(f"{Sex.B_RED}[err]{Sex.END}")
                    print(proc.stderr)

            except Exception as e:
                print(f"{Sex.B_RED}[err] {e}{Sex.END}")

        elif cmd == '/geo2':
            print(f"{Sex.GRAY}[err] usage ::{Sex.END} {Sex.CYAN}/geo2 <args>{Sex.END}")
        elif cmd.startswith('/geo2 '):
            args = rawCmd.split(maxsplit=1)[1]

            import subprocess

            try:
                proc = subprocess.run(
                    ["python3", "python/tools/geo2.py"] + args.split(),
                    text=True,
                    capture_output=True
                )

                if proc.returncode == 0:
                    print(f"{Sex.CYAN}[G2]{Sex.END}")
                    print(proc.stdout)
                else:
                    print(f"{Sex.B_RED}[err]{Sex.END}")
                    print(proc.stderr)

            except Exception as e:
                print(f"{Sex.B_RED}[err] {e}{Sex.END}")

        elif cmd == '/ip':
            print(f"{Sex.GRAY}[err] usage ::{Sex.END} {Sex.CYAN}/ip <args>{Sex.END}")
        elif cmd.startswith('/ip '):
            args = rawCmd.split(maxsplit=1)[1]

            import subprocess

            try:
                proc = subprocess.run(
                    ["python3", "python/tools/ip.py"] + args.split(),
                    text=True,
                    capture_output=True
                )

                if proc.returncode == 0:
                    print(f"{Sex.CYAN}[IP]{Sex.END}")
                    print(proc.stdout)
                else:
                    print(f"{Sex.B_RED}[err]{Sex.END}")
                    print(proc.stderr)

            except Exception as e:
                print(f"{Sex.B_RED}[err] {e}{Sex.END}")

        elif cmd == '/ua':
            print(f"{Sex.GRAY}[err] usage ::{Sex.END} {Sex.CYAN}/ua <args>{Sex.END}")
        elif cmd.startswith('/ua '):
            args = rawCmd.split(maxsplit=1)[1]

            import subprocess

            try:
                proc = subprocess.run(
                    ["python3", "python/tools/ua.py"] + args.split(),
                    text=True,
                    capture_output=True
                )

                if proc.returncode == 0:
                    print(f"{Sex.CYAN}[UA]{Sex.END}")
                    print(proc.stdout)
                else:
                    print(f"{Sex.B_RED}[err]{Sex.END}")
                    print(proc.stderr)

            except Exception as e:
                print(f"{Sex.B_RED}[err] {e}{Sex.END}")





        elif cmd == '/quit':
            print(f"{Sex.GRAY}[stopped...]{Sex.END}")
            self.running = False

        else:
            print(f"{Sex.B_RED}unknown cmd{Sex.END} {Sex.GRAY}::{Sex.END} {Sex.PURPLE}{cmd}{Sex.END}\n")



    def cleanScreen(self):
        if sys.platform.startswith('win'):
            os.system('cls')
        else:
            os.system('clear')

    def cleanMem(self):
        with self.seenMessagesLock:
            self.messageHistory.clear()
            self.seenMessages.clear()

    def start(self):
        self.running = True

        if self.myOnion:
            self.knownPeers.add(f"{self.myOnion}:{self.port}")

        threading.Thread(target=self.startServer, daemon=True).start()
        time.sleep(1)

        for bootstrap in BOOTSTRAP_NODES:
            threading.Thread(target=self.connectToPeer, args=(bootstrap,), daemon=True).start()
            time.sleep(0.5)

        threading.Thread(target=self.discoveryLoop, daemon=True).start()
        threading.Thread(target=self.heartbeatLoop, daemon=True).start()
        threading.Thread(target=self.cleanupLoop, daemon=True).start()
        if self.obfuscateMode:
            self.startObfuscate()

        if self.upnpEnabled:
            self.setupUPnP()

        if self.mediaEnabled:
            self.initialMedia()

        self.bannerVyx()
        self.inputLoop()

    def bannerVyx(self):
        if self.quietMode:
            return
        print(f"\n{Sex.GRAY}[p2pC] Node decentralized ::{Sex.END} {Sex.B_RED}{datetime.now().date()}{Sex.END}\n")
        print(f"{Sex.GRAY}This is a {Sex.CYAN}decentralized version{Sex.END}\n{Sex.GRAY}Without dependence on a{Sex.END} {Sex.CYAN}central server{Sex.END}\n{Sex.GRAY}Its development is still in its{Sex.END} {Sex.PURPLE}early stages{Sex.END}\n{Sex.GRAY}There may be connection and data issues.{Sex.END}")
        print(f"{Sex.CYAN}Version{Sex.END} {Sex.GRAY}::{Sex.END} {Sex.PURPLE}2.67{Sex.END}\n")
        print(f"{Sex.GRAY}user     ::{Sex.END} {Sex.PURPLE}{self.username}{Sex.END}")
        print(f"{Sex.GRAY}port     ::{Sex.END} {self.port}{Sex.END}")
        if self.myOnion:
            print(f"{Sex.GRAY}addr     ::{Sex.END} {self.myOnion}{Sex.END}")
        print(f"{Sex.GRAY}peers    ::{Sex.END} {len(self.peers)}{Sex.END}")
        print(f"\n{Sex.GRAY}  [commands]{Sex.END}")
        print(f"  /who   {Sex.GRAY}::{Sex.END}  {Sex.CYAN}show all users online in room{Sex.END}")
        print(f"  /help  {Sex.GRAY}::{Sex.END}  {Sex.CYAN}show all commands availables{Sex.END}")
        print(f"  /quit  {Sex.GRAY}::{Sex.END}  {Sex.CYAN}leave the room{Sex.END}\n\n")

    def stop(self):
        self.running = False

        with self.peersLock:
            for peer in self.peers.values():
                try:
                    peer['conn'].close()
                except:
                    pass

        if self.serverSock:
            try:
                self.serverSock.close()
            except:
                pass

        if self.upnpEnabled:
            self.closeUPnP()

        with self.privateKeysLock:
            for key in self.privateKeys.keys():
                self.privateKeys[key] = bytearray(os.urandom(120))
            self.privateKeys.clear()

        print(f"{Sex.GRAY}[shutdown] node stopped{Sex.END}")

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='p2p node')
    parser.add_argument('-p', '--port', type=int, default=8888, help='ports use to chat server')
    parser.add_argument('-u', '--username', required=True, help='username visible in chat')
    parser.add_argument('-P', '--password', help='password common')
    parser.add_argument('-k', '--key', help='group key generated')
    parser.add_argument('-gk', '--genkey', action='store_true', help='gen password hexChars')
    parser.add_argument('-o', '--onion', help='your .onion addr')
    parser.add_argument('-v', '--verify', type=int, nargs='?', const=128, metavar='SIZE', help='enable verification fingerprint')
    parser.add_argument('-S', '--stealth', action='store_true', help='hidden metadata')
    parser.add_argument('-pa', '--paran', type=int, metavar='SECONDS', help='auto destruct messages')
    parser.add_argument('-O', '--obfuscate', action='store_true', help='fake trafic')
    parser.add_argument('-r', '--ratelimit', type=int, metavar='MAX', default=0, help='max messages/min (0=off)')
    parser.add_argument('-t', '--timeout', type=int, default=280, metavar='SEC', help='peer timeout seconds')
    parser.add_argument('-w', '--whitelist', type=str, metavar='USERS', help='allowed usernames')
    parser.add_argument('-B', '--blacklist', type=str, metavar='ONIONS', help='bloqued onion addresses')
    parser.add_argument('-l', '--log', type=str, metavar='FILE', help='save logs to file')
    parser.add_argument('-q', '--quiet', action='store_true', help='quiet mode[only show chats messages]')
    parser.add_argument('-b', '--bootstrap', action='append', help='bootstrap peer')
    parser.add_argument('-F', '--forward', action='store_true', help='enable UPnp port forwarding')
    parser.add_argument('-R', '--relay', action='store_true', help='enable relay/bridge mode')
    parser.add_argument('-M', '--media', action='store_true', help='enable media transfer')
    #parser.add_argument('-s', '--show', action='store_true', help='show messages')
    parser.add_argument('-x', '--xor', type=str, default=None, help='xor encrypt messages')
    parser.add_argument('-m', '--max', type=int, default=200, help='max peers')
    parser.add_argument('-ms', '--msghist', type=int, default=300, help='maximum history messages for the new user')
    parser.add_argument('-g', '--gossip', type=int, default=3, help='goosip interval seconds')
    parser.add_argument('-H', '--heartbeat', type=int, default=40, help='heartbeat ping conection interval seconds')

    args = parser.parse_args()

    if args.genkey:
        newKey = genSecKey(44)
        showKey(newKey)
        sys.exit(0)

    if not args.username:
        print(f"{Sex.B_RED}[WARNING] :: -u | --username{Sex.END} {Sex.CYAN}is required{Sex.END}")
        sys.exit(1)

    if args.password and args.key:
        print(f"{Sex.B_RED}[WARNING]{Sex.END} :: {Sex.CYAN}cannot use both -P and -k [choose one]{Sex.END}")
        sys.exit(1)

    if not args.password and not args.key:
        print(f"{Sex.B_RED}[WARNING]{Sex.END} :: {Sex.CYAN}provide password [-P] or key [-k] please{Sex.END}\n{Sex.GRAY}[Generation Key] :: {Sex.END} {Sex.PURPLE}python python/p2pNode.py [--genkey] or [-gk]{Sex.END}")
        sys.exit(1)

    if args.key:
        if not validateKey(args.key):
            print(f"{Sex.B_RED}[WARING]{Sex.END} :: {Sex.B_RED}invalid key format!{Sex.END}")
            sys.exit(1)
        sharedKeyBytes = keyToBytes(args.key)
        credentialToUse = sharedKeyBytes
        usePassword = False
    else:
        credentialToUse = args.password
        usePassword = True

    if args.max > 20000:
        print(f"{Sex.N_RED}[WARNING] :: -m  | --max{Sex.END}\n{Sex.CYAN}[Default :: 200]{Sex.END}\nAre you sure you can place more than 20k users?\nOK!\n\n")

    if args.msghist > 50000:
        print(f"{Sex.N_RED}[WARNING] :: -ms | --msghist{Sex.END}\n{Sex.CYAN}[Default :: 300]{Sex.END}\nAre you sure you want to set more than 20k of cache history?\n(Be careful with your RAM)\n\n")

    if args.gossip > 50:
        print(f"{Sex.N_RED}[WARNING] :: -g  | --goosip{Sex.END}\n{Sex.CYAN}[Default :: 3]{Sex.END}\nI recommend setting it between 1-10\nexceeding that level makes waiting for the user to connect annoying\n\n")

    if args.heartbeat > 500:
        print(f"{Sex.N_RED}[WARNING] :: -H  | --heartbeat{Sex.END}\n{Sex.CYAN}[Default :: 40]{Sex.END}\nThis helps keep the connection alive and warns of timeouts due to inactivity\nI recommend 40-100\n\n")

    MAX_PEERS = args.max
    MESSAGE_HISTORY = args.msghist
    GOSSIP_INTERVAL = args.gossip
    HEARTBEAT_INTERVAL = args.heartbeat

    if args.bootstrap:
        BOOTSTRAP_NODES.extend(args.bootstrap)

    try:
        testSock = socket.socket()
        testSock.settimeout(2)
        testSock.connect(('127.0.0.1', 9050))
        testSock.close()
    except:
        print(f"{Sex.B_RED}[!x!] tor not running :: 127.0.0.1:9050{Sex.END}")
        sys.exit(1)

    node = P2PNode(
        port=args.port,
        username=args.username,
        password=credentialToUse if usePassword else None,
        sharedKey=credentialToUse if not usePassword else None,
        onion=args.onion
    )
    if args.xor:
        node.xorKey = args.xor.encode() if isinstance(args.xor, str) else args.xor
    #node.xorKey = args.xor

    if args.verify:
        node.genFingerprint(args.verify)

    if hasattr(args, 'stealth') and args.stealth:
        node.stealthMode = True
        print(f"{Sex.GRAY}[AV][Stealth]{Sex.END}       :: {Sex.CYAN}metadata hidden{Sex.END}")

    if hasattr(args, 'paran') and args.paran:
        node.paranMode = True
        node.paranDelay = args.paran
        print(f"{Sex.GRAY}[AV][ParanMode]{Sex.END}     :: {Sex.CYAN}autodelete msg's in {args.paran}s{Sex.END}")

    if hasattr(args, 'obfuscate') and args.obfuscate:
        node.obfuscateMode = True

    if hasattr(args, 'ratelimit') and args.ratelimit:
        node.rateLimitMax = args.ratelimit
        print(f"{Sex.GRAY}[AV][RateLimit]{Sex.END}     :: {Sex.CYAN}max {args.ratelimit} msg's/min{Sex.END}")

    if args.timeout:
        node.peerTimeout = args.timeout

    if args.whitelist:
        node.whitelist = set(args.whitelist.split(','))
        if not args.quiet:
            print(f"{Sex.GRAY}[AV][Whitelist]{Sex.END}     :: {Sex.CYAN}[{', '.join(node.whitelist)}]{Sex.END}")

    if args.blacklist:
        node.blacklist = set(args.blacklist.split(','))
        if not args.quiet:
            print(f"{Sex.GRAY}[AV][Blacklist]{Sex.END}     :: {Sex.CYAN}[{', '.join(node.blacklist)}]{Sex.END}")

    if args.log:
        node.logFile = args.log
        node.writeLog("### logs ###")
        if not args.quiet:
            print(f"{Sex.GRAY}[AV][Logging]{Sex.END}       :: {Sex.CYAN}{args.log}{Sex.END}")

    if args.quiet:
        node.quietMode = True

    if args.forward:
        node.upnpEnabled = True

    if args.relay:
        node.relayMode = True
        if not args.quiet:
            print(f"{Sex.GRAY}[AV][RelayMode]{Sex.END}     :: {Sex.CYAN}Bridge Mode{Sex.END}")

    if args.media:
        node.mediaEnabled = True
        if not args.quiet:
            print(f"{Sex.GRAY}[AV][Media]{Sex.END}         :: {Sex.CYAN}File transfer{Sex.END}")



    node.start()

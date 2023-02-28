# Database
import json
import aiofiles

# Networking
import websockets
import aiohttp
import socket

# Misc
import os
import asyncio
import random
import shutil
import sys
import logging
import traceback
import time

# Signing
from Crypto.PublicKey import ECC
from nacl.signing import SigningKey
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
# Block hashes/address generation
from Crypto.Hash import SHA256
from Crypto.Hash import BLAKE2b
#  Encrypted communication
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
# Address generation
import base64
import zlib

try:
    print(f'Debugging enabled: {os.environ["debug"]}')
    logging.basicConfig(level=logging.DEBUG)

except KeyError:
    logging.basicConfig(level=logging.INFO)

if __name__ == "__main__":
    # Other MurraxCoin components
    from bootstrapServer import bootstrap_server

# Configuration Variables
entrypoints = ["ws://murraxcoin.murraygrov.es:6969"]  # List of known nodes that can be used to "enter" the network.
ledgerDir = "data/Accounts/"  # Path to the directory where the ledger will be stored (must end in /)
bootstrapDir = "-Bootstrap/".join(ledgerDir.rsplit("/", 1))
privateFile = "data/nodeKey"  # Path of the node's private key
CONSENSUS_PERCENT = 0.65  # Float representing what percent of the online voting nodes must agree with a transaction for it to be confirmed.
BLOCK_TIMEOUT = 30  # Seconds before a block will time out if still unconfirmed
force_valid_blocks = [
    "e15e7c4f0fcf6ce79203317f83a5a64f6700f0396d27200cbfcab12bdeac5dd8461850db362444cc6b1d3dd07afcbe2b3a19d10a9fecbdd5e6668d21c14031fa",
    "ee199fee5352e1a24728c077cd0d5761de2660e075b5b648abec6b297e17c4c930995108d2aa80309dd300c47f4d742624d38dda0ee99a5105d3e68afe2310f2",
    "9417e70de575921e2b6ee220e27ca5e97d637268c2ca13df3363de5a1d5999d2de4009e16b366f4fb186624e3690601340608235a6aba0cd60aa9084cb36cd9f",
    "33a911e112950f535949938b0ed9f620c945419f7ab83ec77007ff5d3b9a6f97d4e074dc604d25e0f09dd2aceb9ab0a5eeda9742594586cf21682c5eb79f0969",
    "862cde47e07bba8e927083a0108d473c49aad43ed27834c5f3b8c41d49ed54237302f22008f82dbe98e7b8550a38e7b00d2ada76c8ffb4aa43cd4af4f2599eaf",
    "1a648280ee9c29afedc18a46c593ca82e77a66e5b9f5128d36a43c25a8c4975ecde72a33ba8fd45bc504facee080796b87287d86b80800e5d383f8eab56a17f8",
    "37433095547d8067bede4ca5ff193aaa81ec4b3754f844b1d79a79a4020838ff526a30b9cfc05899481803218e999527d74589a63e510a128cafa68e9ad0488f",
    "1739bccabaddf2384644a362042a939142d35d66940fbe56dae90d01ff4786764a205543cfdb1f7b6caeb0902d569f421520c617f1b5b714f193178d8830618f"
]  # List of invalid blocks that should be accepted as valid.

try:
    f = open(privateFile, "rb")
    privateKey = SigningKey(f.read())
    f.close()

except:
    seed = os.urandom(32)
    privateKey = SigningKey(seed)
    f = open(privateFile, "wb+")
    f.write(seed)
    f.close()

publicKey = privateKey.verify_key

addressChecksum = zlib.adler32(publicKey.encode()).to_bytes(4, byteorder="big")
addressChecksum = base64.b32encode(addressChecksum).decode("utf-8").replace("=", "").lower()
address = base64.b32encode(publicKey.encode()).decode("utf-8").replace("=", "").lower()
publicKeyStr = f"mxc_{address}{addressChecksum}"

# Create the ledger directory
os.makedirs(ledgerDir, exist_ok=True)

# Initialise global variables
nodes = {}  # Dictionary of all connected nodes. Structure follows:
            #   {ip : [websocket, weight]}
            #     ip - str - The IP/hostname that the node can be reached by. Includes port and "ws://" prefix
            #     websocket - websockets.Websocket - the websocket that the node can be reached on.

sendSubscriptions = {}  # Dictionary of nodes that should be alerted when an account is referenced in a send transaction. Structure follows:
                        #   {address : [websocket,...]}
                        #     address - str - MXC address that is being monitored
                        #     websocket - websockets.Websocket - the websocket that the node can be reached on.

votePool = {}   # Dictionary of all ongoing votes. Structure follows:
                  # {voteID : [consensusWeight, block, [[address, weight],...]]}
                    # voteID - Float - Randomly generated ID for each voting round.
                    # consensusWeight - Float - Represents the value that the total voted weight must exceed for a block to be confirmed.
                    # address - Str - The MXC address of the voting node.
                    # weight - Float - The voting weight of the voting node. Negative if voting against.

lockedAddresses = {}  # Key is an address that has a pending transaction, hence no new transactions can be submitted. Value is the timestamp at which it will time out.

sessionKeys = {}

ip = -1
myPort = -1

votingWeights = {}

background_tasks = set()

try:
    f = open("handshake_key.pem", "rb")
    handshakeKey = RSA.import_key(f.read())
    f.close()

except FileNotFoundError:
    handshakeKey = RSA.generate(2048)
    toWrite = handshakeKey.export_key()
    f = open("handshake_key.pem", "wb+")
    f.write(toWrite)
    f.close()
    del toWrite

handshakePublicKey = handshakeKey.publickey()
handshakePublicKeyStr = handshakePublicKey.export_key()
handshakeCipher = PKCS1_OAEP.new(handshakeKey)


class DoublePrevious(Exception):
    """Raised when the node encounters a transaction that uses a previous that has already been used as a previous"""
    def __init__(self, block_1, block_2):
        self.block_1 = block_1
        self.block_2 = block_2


class DuplicateTransaction(Exception):
    """Raised when a transaction has already been seen"""
    def __init__(self, block):
        self.block = block


async def copytree(src, dst, symlinks=False, ignore=None):
    if not os.path.exists(dst):
        os.makedirs(dst)
    for item in os.listdir(src):
        s = os.path.join(src, item)
        d = os.path.join(dst, item)
        if os.path.isdir(s):
            copytree(s, d, symlinks, ignore)
        else:
            if not os.path.exists(d) or os.stat(s).st_mtime - os.stat(d).st_mtime > 1:
                shutil.copy2(s, d)


class websocketSecure:
    def __init__(self, url):
        self.url = url

    async def initiateConnection(self):
        try:
            self.websocket = await websockets.connect(self.url)
        except OSError:
            raise TimeoutError
        await self.websocket.send(handshakePublicKeyStr)
        handshakeData = await self.websocket.recv()
        logging.debug(f"Handshake Data: {handshakeData}")
        handshakeData = json.loads(handshakeData)

        sessionKey = base64.b64decode(handshakeData["sessionKey"].encode('utf-8'))
        #sessionKey = bytes.fromhex(handshakeData["sessionKey"])
        self.sessionKey = handshakeCipher.decrypt(sessionKey)

    @classmethod
    async def connect(cls, url):
        self = websocketSecure(url)
        await self.initiateConnection()
        for i in range(200):
            try:
                self.sessionKey
                return self

            except:
                await asyncio.sleep(0.1)

        raise TimeoutError

    async def recv(self):
        data = await self.websocket.recv()
        ciphertext, tag, nonce = data.split("|||")
        ciphertext, tag, nonce = base64.b64decode(ciphertext.encode("utf-8")), base64.b64decode(tag), base64.b64decode(nonce)
        cipher = AES.new(self.sessionKey, AES.MODE_GCM, nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        plaintext = plaintext.decode("utf-8")

        return plaintext

    async def send(self, plaintext):
        cipher = AES.new(self.sessionKey, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
        await self.websocket.send(base64.b64encode(ciphertext).decode("utf-8") + "|||" + base64.b64encode(tag).decode("utf-8") + "|||" + base64.b64encode(cipher.nonce).decode("utf-8"))

    async def close(self):
        await self.websocket.close()


async def unlock_address(address: str, delay: int):  # Unlocks an address and deletes a pending transaction after it times out
    await asyncio.sleep(delay)
    try:
        lockedAddresses.pop(address)
        logging.debug(f"Address {address} unlocked")
    except KeyError:
        logging.debug(f"Address {address} was not locked")

    for election in votePool.keys():
        if votePool[election][2]["address"] == address:
            votePool.pop(election)
            logging.debug(f"Address {address} removed from the vote pool")
            break


async def balance(data: dict, **kwargs) -> str:
    """Returns an account's balance"""

    address = data["address"]

    try:
        block = await getHead(address)

    except FileNotFoundError:
        response = {"type": "rejection", "address": f"{address}", "reason": "addressNonExistent"}
        return response

    response = {"type": "info", "address": address, "balance": f"{block['balance']}"}
    return response


async def broadcast(data, **kwargs):
    """Broadcast a verified transaction to other nodes"""

    broadcastID = str(random.randint(0, 99999999999999999999))
    broadcastID = "0"*(20-len(broadcastID)) + broadcastID

    validNodesStr = ""
    validNodes = []
    for node in nodes:
        ws = nodes[node][0]
        try:
            await ws.send('{"type": "ping"}')
            resp = await ws.recv()
            if json.loads(resp)["type"] == "confirm":
                logging.debug("Node is available for broadcast: ", node)
                validNodesStr = validNodesStr + "|" + node
                validNodes.append(node)

        except Exception as e:
            logging.info("Error while contacting a node for broadcast: " + str(e))
            pass

    packet = {"type": "vote", "voteID": broadcastID, "vote": "for", "block": json.dumps(data), "address": publicKeyStr}
    signature = await genSignature(packet, privateKey)
    logging.info("Broadcasting: " + json.dumps(packet))
    packet["signature"] = signature

    weight = await balance({"address": publicKeyStr})
    weight = float(weight["balance"])

    offline = False if len(nodes) == 0 else True  # If nodes are connected but none are responsive, reboot
    onlineWeight = weight
    for node in nodes:
        ws = nodes[node][0]
        try:
            await ws.send('{"type": "ping"}')
            resp = await ws.recv()
            offline = False
            if json.loads(resp)["type"] == "confirm":
                logging.debug("Node is available for broadcast: ", node)

        except Exception as e:
            logging.debug("Error while contacting a node for broadcast: " + str(e))
            nodes.pop(node)
            pass
        onlineWeight += nodes[node][2]

    if offline:
        await asyncio.sleep(60)
        os.execv(sys.argv[0], sys.argv)

    votePool[broadcastID] = [onlineWeight*CONSENSUS_PERCENT, weight, data, [[packet, weight]], False]
    if votePool[broadcastID][1] >= votePool[broadcastID][0]:
        logging.info("Consensus reached: " + str(votePool[broadcastID]))
        logging.info(f"Transaction: {data}")
        if data["type"] != "open":
            if data["type"] == "send":
                if data["link"] in sendSubscriptions:
                    head = await getHead(data["address"])
                    sendAlert = {"type": "sendAlert", "address": data["link"],
                                 "sendAmount": str(float(head["balance"]) - float(data["balance"])),
                                 "link": f"{data['address']}/{data['id']}"}

                    sendAlert = json.dumps(sendAlert)
                    global sessionKeys

                    for ws in sendSubscriptions[data["link"]]:
                        try:
                            session_key = sessionKeys[ws]
                            cipher_aes = AES.new(session_key, AES.MODE_GCM)
                            ciphertext, tag = cipher_aes.encrypt_and_digest(sendAlert.encode("utf-8"))
                            await ws.send(base64.b64encode(ciphertext).decode("utf-8") + "|||" + base64.b64encode(tag).decode("utf-8") + "|||" + base64.b64encode(cipher_aes.nonce).decode("utf-8"))
                            logging.info("Sent a send alert for that transaction")

                        except websockets.exceptions.ConnectionClosedError:
                            logging.info("Send subscription unavailable")
                            pass
            f = await aiofiles.open(f"{ledgerDir}{data['address']}", "a")
            await f.write("\n" + json.dumps(data))
            await f.close()

        else:
            f = await aiofiles.open(f"{ledgerDir}{data['address']}", "w+")
            await f.write(json.dumps(data))
            await f.close()

        votePool[broadcastID][4] = True
        lockedAddresses.pop(data["address"])

    for node in validNodes:
        await nodes[node][0].send(json.dumps(packet))
        resp = await ws.recv()
        try:
            resp = json.loads(resp)
            if resp["type"] != "confirm":
                raise Exception(f"Invalid response: {json.dumps(resp)}")

            logging.info("Vote received by ", node)

        except TimeoutError:
            logging.info("Vote not received by ", node)

        except Exception as e:
            logging.warning("Exception while receiving vote confirmation")
            logging.debug(e)


# Return any send transactions that have not been received by an account
async def checkForPendingSend(data, **kwargs):
    address = data["address"]

    received = []
    accounts = os.listdir(ledgerDir)
    if address in accounts:
        f = await aiofiles.open(ledgerDir + address)
        data = await f.read()
        await f.close()

        data = data.splitlines()
        for block in data:
            block = json.loads(block)
            if block["type"] == "receive":
                received.append(block["link"])

            if block["type"] == "open":
                received.append(block["link"])

    for i in accounts:
        f = await aiofiles.open(f"{ledgerDir}{i}")
        blocks = await f.read()
        await f.close()
        blocks = blocks.splitlines()
        for block in blocks:
            block = json.loads(block)
            if f'{block["address"]}/{block["id"]}' in received:
                continue

            if block["type"] == "send":
                if block["link"] == address:
                    amount = await getBlock(block["address"], block["previous"])
                    amount = float(amount["balance"]) - float(block["balance"])

                    resp = {"type": "pendingSend", "link": f"{block['address']}/{block['id']}", "sendAmount": amount}
                    return resp

    response = {"type": "pendingSend", "link": "", "sendAmount": ""}
    return response


async def change(data, **kwargs):
    signature = data["signature"]
    address = data["address"]
    blockID = data["id"]

    valid = await verifySignature(signature, address, data)
    if not valid:
        toRespond = {"type": "rejection", "address": f"{address}", "id": f"{blockID}", "reason": "signature"}
        return toRespond

    preID = data.copy()
    preID.pop("signature")
    preID.pop("id")

    hasher = BLAKE2b.new(digest_bits=512)
    realID = hasher.update(json.dumps(preID).encode("utf-8")).hexdigest()
    if blockID != realID:
        toRespond = {"type": "rejection", "address": f"{address}", "id": f"{blockID}", "reason": "id"}
        return toRespond

    previousBlock = await getBlock(address, data["previous"])
    # Check that balance has not changed
    if float(data["balance"]) != float(previousBlock["balance"]):
        toRespond = {"type": "rejection", "address": f"{address}", "id": f"{blockID}", "reason": "balance"}
        return toRespond

    if data["representative"] not in os.listdir(ledgerDir):  # If account to be delegated to does not exist
        toRespond = {"type": "rejection", "address": f"{address}", "id": f"{blockID}", "reason": "link"}
        return toRespond

    toRespond = {"type": "confirm", "action": "delegate", "address": address, "id": blockID}
    return toRespond


# Return a list of available nodes
async def fetchNodes(**kwargs):
    global nodes
    nodeAddresses = ""
    for node in nodes:
        nodeAddresses = nodeAddresses + "|" + node

    response = {"type": "confirm", "action": "fetchNodes", "nodes": nodeAddresses}
    return response


async def getAddress(data, publicKey):
    """ Get a public key's readable address
    Addresses are SHA256 hashes of public keys, which are then encoded in base32, with an adler32 checksum at the end.
    E.g. mxc_ojapkckckyg7j7mimnojepct4kfbxxxgl5ktvtsxgvkb3zjngk2q6weq5la """

    publicKey = publicKey.split(" ")
    publicKey = "-----BEGIN PUBLIC KEY-----\n" + publicKey[0] + "\n" + publicKey[1] + "\n-----END PUBLIC KEY-----"
    publicKey = ECC.import_key(publicKey)

    publicKeyBin = publicKey.export_key(format="DER", compress=True)
    publicKeyHash = SHA256.new(publicKeyBin).digest()
    addressChecksum = zlib.adler32(publicKeyHash).to_bytes(4, byteorder="big")
    addressChecksum = base64.b32encode(addressChecksum).decode("utf-8").replace("=", "").lower()
    address = base64.b32encode(publicKeyHash).decode("utf-8").replace("=", "").lower()
    address = f"mxc_{address}{addressChecksum}"
    return address


async def genSignature(data, privateKey):
    data = json.dumps(data).encode()
    signature = privateKey.sign(data).signature
    signature = hex(int.from_bytes(signature, "little"))

    return signature


# Return a block belonging to the account (address) with block ID (blockID)
async def getBlock(address, blockID, directory=ledgerDir):
    f = await aiofiles.open(f"{directory}{address}")
    fileStr = await f.read()
    await f.close()
    fileStr = fileStr.splitlines()

    blocks = []
    for block in fileStr:
        if not block.startswith("address: "):
            blocks.append(json.loads(block))

    for block in blocks:
        if block["id"] == blockID:
            return block

    logging.info(f"Block not found: {address}, {blockID}, {directory}")

async def getBlockRequest(data, ws):
    address = data["address"]
    block = data["block"]
    
    try:
        block = await getBlock(address, block)
    
    except FileNotFoundError:
        return {"type": "rejection", "originalRequest": "getBlock", "address": address, "block": block, "reason": "accountNonExistent"}
    
    if block == None:
        return {"type": "rejection", "originalRequest": "getBlock", "address": address, "block": block, "reason": "blockNonExistent"}
    
    response = {"type": "getBlock", "block": block}
    return response

async def getPrevious(data, **kwargs):
    try:
        head = await getHead(data["address"])

    except FileNotFoundError:
        return {"type": "rejection", "originalRequest": "getPrevious", address: data["address"], "reason": "accountNonExistent"}
    
    address = data["address"]
    previous = head["id"]
    response = {"type": "previous", "address": address, "link": previous}
    return response


async def getRepresentative(data, **kwargs):  # Get address of an account's representative
    address = data["address"]
    try:
        head = await getHead(address)
        representative = head["representative"]

    except FileNotFoundError:
        return {"type": "rejection", "originalRequest": "getRepresentative", address: address, "reason": "accountNonExistent"}

    return {"type": "info", "address": address, "representative": representative}


# Get the head block of an account (the most recent block)
async def getHead(address, directory=ledgerDir, **kwargs):
    f = await aiofiles.open(f"{directory}{address}")
    fileStr = await f.read()
    await f.close()
    fileStr = fileStr.splitlines()

    blocks = []
    for block in fileStr:
        if not block.startswith("address: "):
            blocks.append(json.loads(block))

    if len(blocks) == 1:
        return blocks[0]

    used_previouses = {}

    # Sort blocks in order
    isSorted = False
    while not isSorted:
        isSorted = True
        for i in range(1, len(blocks)):
            previous = blocks[i]["previous"]
            if previous in used_previouses:
                if blocks[i] == used_previouses[previous]:
                    raise DuplicateTransaction(blocks[i])

                raise DoublePrevious(blocks[i], used_previouses[previous])

            used_previouses[previous] = blocks[i]
            if previous == "0"*20:  # if broken, change to 145
                blocks.insert(0, blocks.pop(i))
                continue

            if blocks[i-1]["id"] == previous:
                continue

            isSorted = False

            for x in range(len(blocks)):
                if blocks[x]["id"] == previous:
                    blocks.insert(x+1, blocks.pop(i))
                    break

    return blocks[-1]


async def getHeadRequest(data, ws):
    address = data["address"]
    try:
        block = await getHead(address)
        
    except FileNotFoundError:
        response = {"type": "rejection", "address": f"{address}", "reason": "addressNonExistent"}
        return response
    
    response = {"type": "getHead", "block": block}
    return response


async def initiate(data, **kwargs):
    if data["type"] == "change":
        response = await change(data)

    elif data["type"] == "open":
        response = await openAccount(data)

    elif data["type"] == "receive":
        response = await receive(data)

    else:
        response = await send(data)

    locked = data["address"] in lockedAddresses

    if response["type"] == "confirm" and not locked:
        lockedAddresses[data["address"]] = int(time.time()) + BLOCK_TIMEOUT  # Time out transaction after 30 seconds of being unconfirmed.
        task = asyncio.create_task(unlock_address(data["address"], BLOCK_TIMEOUT))
        background_tasks.add(task)  # Prevents it being garbage collected
        task.add_done_callback(background_tasks.discard)

        await broadcast(data)

    elif locked:
        response = {"type": "rejection", "reason": "This address has a pending transaction.", "latest_unlock_time": lockedAddresses[data["address"]]}

    return response


# Process an open transaction
async def openAccount(data):
    signature = data["signature"]
    address = data["address"]
    blockID = data["id"]

    valid = await verifySignature(signature, address, data)
    if not valid:
        toRespond = {"type": "rejection", "address": f"{address}", "id": f"{blockID}", "reason": "signature"}
        return toRespond
    
    if os.path.exists(f"{ledgerDir}{address}"):
        toRespond = {"type": "rejection", "address": f"{address}", "id": f"{blockID}", "reason": "alreadyExists"}
        return toRespond

    preID = data.copy()
    preID.pop("signature")
    preID.pop("id")

    hasher = BLAKE2b.new(digest_bits=512)
    realID = hasher.update(json.dumps(preID).encode("utf-8")).hexdigest()
    if blockID != realID:
        toRespond = {"type": "rejection", "address": f"{address}", "id": f"{blockID}", "reason": "id"}
        return toRespond

    sendingAddress, sendingBlock = data["link"].split("/")
    sendingBlock = await getBlock(sendingAddress, sendingBlock)

    # Check that send block is valid
    valid = await verifySignature(sendingBlock["signature"], sendingAddress, sendingBlock)
    if not valid:
        toRespond = {"type": "rejection", "address": f"{address}", "id": f"{blockID}", "reason": "sendSignature"}
        return toRespond

    previousBlock = await getBlock(sendingAddress, sendingBlock["previous"])
    sendAmount = float(previousBlock["balance"]) - float(sendingBlock["balance"])

    if float(data["balance"]) != float(sendAmount):
        response = {"type": "rejection", "address": f"{address}", "id": f"{blockID}", "reason": "invalidBalance"}

    elif data["previous"] != "0"*20:
        response = {"type": "rejection", "address": f"{address}", "id": f"{blockID}", "reason": "invalidPrevious"}

    else:
        response = {"type": "confirm", "action": "open", "address": f"{address}", "id": f"{blockID}"}

    return response


async def ping(**kwargs):
    return {"type": "confirm", "action": "ping"}


# Process a receive transaction
async def receive(data):
    signature = data["signature"]
    address = data["address"]
    blockID = data["id"]

    valid = await verifySignature(signature, address, data)
    if not valid:
        toRespond = {"type": "rejection", "address": f"{address}", "id": f"{blockID}", "reason": "signature"}
        return toRespond

    preID = data.copy()
    preID.pop("signature")
    preID.pop("id")

    hasher = BLAKE2b.new(digest_bits=512)
    realID = hasher.update(json.dumps(preID).encode("utf-8")).hexdigest()
    if blockID != realID:
        toRespond = {"type": "rejection", "address": "{address}", "id": "{blockID}", "reason": "id"}
        return toRespond

    sendingAddress, sendingBlock = data["link"].split("/")
    sendingBlock = await getBlock(sendingAddress, sendingBlock)

    # Check that send block is valid
    valid = await verifySignature(sendingBlock["signature"], sendingAddress, sendingBlock)
    if not valid:
        toRespond = {"type": "rejection", "address": f"{address}", "id": f"{blockID}", "reason": "sendSignature"}
        return toRespond

    try:
        f = await aiofiles.open(f"{ledgerDir}{address}")
        blocks = await f.read()
        await f.close()

    except FileNotFoundError:
        return {"type": "rejection", "address": f"{address}", "id": f"{blockID}", "reason": "addressNonExistent"}
    
    blocks = blocks.splitlines()
    for block in blocks:
        if json.loads(block)["type"] == "genesis":
            continue

        if json.loads(block)["link"] == data["link"]:
            response = {"type": "rejection", "address": address, "id": blockID, "reason": "doubleReceive"}
            return response

    previousBlock = await getBlock(sendingAddress, sendingBlock["previous"])
    sendAmount = float(previousBlock["balance"]) - float(sendingBlock["balance"])

    head = await getHead(address)
    if float(data["balance"]) != float(head["balance"]) + float(sendAmount):
        response = {"type": "rejection", "address": f"{address}", "id": f"{blockID}", "reason": "invalidBalance"}

    elif data["previous"] != head["id"]:
        response = {"type": "rejection", "address": f"{address}", "id": f"{blockID}", "reason": "invalidPrevious"}

    else:
        response = {"type": "confirm", "action": "receive", "address": f"{address}", "id": f"{blockID}"}

    return response


# Register myself with specified node
async def registerMyself(node, doRespond):
    global myPort
    global ip
    logging.info(f"Registering with {node}")
    websocket = await websocketSecure.connect(node)
    await websocket.send(f'{{"type": "registerNode", "port": "{myPort}", "address": "{publicKeyStr}","respond": "{str(doRespond)}"}}')
    resp = await websocket.recv()
    if json.loads(resp)["type"] == "confirm":
        logging.info(f"Node registered with: {node}")
        global nodes
        nodes[node][0] = websocket

        await websocket.send('{"type": "fetchNodes"}')
        newNodes = await websocket.recv()
        logging.debug(newNodes)
        newNodes = json.loads(newNodes)["nodes"].split("|")[1:]
        logging.debug(newNodes)
        for node in newNodes:
            nodeIP = node.replace("ws://", "").split(":")[0]
            isLocalMachine = (nodeIP == "localhost" or nodeIP == "127.0.0.1" or nodeIP == ip) and str(myPort) == str(node.split(":")[2])
            if node not in nodes and not isLocalMachine:
                await registerMyself(node, doRespond=True)

    else:
        await websocket.close()
        logging.debug(f"Failed to register with: {node}")

    logging.debug("Done registering")


async def registerNode(data, ws):
    response = {"type": "confirm", "action": "registerNode"}
    try:
        weight = float(votingWeights[data["address"]])

    except KeyError:  # No one has delegated the node's address
        weight = 0

    nodes[f"ws://{ws.remote_address[0]}:{data['port']}"] = [None, data["address"], weight]
    if data["respond"] == "True":
        await registerMyself(f"ws://{ws.remote_address[0]}:{data['port']}", doRespond=False)

    return response


# Processes a send transaction
async def send(data):
    signature = data["signature"]
    address = data["address"]
    blockID = data["id"]

    valid = await verifySignature(signature, address, data)
    if not valid:
        response = {"type": "rejection", "address": f"{address}", "id": f"{blockID}", "reason": "signature"}
        return response

    preID = data.copy()
    preID.pop("signature")
    preID.pop("id")

    hasher = BLAKE2b.new(digest_bits=512)
    realID = hasher.update(json.dumps(preID).encode("utf-8")).hexdigest()
    try:
        head = await getHead(address)
    except FileNotFoundError:
        return {"type": "rejection", "address": f"{address}", "id": f"{blockID}", "reason": "addressNonExistent"}

    if blockID != realID:
        response = {"type": "rejection", "address": f"{address}", "id": f"{blockID}", "reason": "id"}

    elif float(head["balance"]) < float(data["balance"]):
        response = {"type": "rejection", "address": f"{address}", "id": f"{blockID}", "reason": "balance"}

    elif float(data["balance"]) < 0:
        response = {"type": "rejection", "address": f"{address}", "id": f"{blockID}", "reason": "balance"}

    elif head["id"] != data["previous"]:
        response = {"type": "rejection", "address": f"{address}", "id": f"{blockID}", "reason": "invalidPrevious"}

    else:
        response = {"type": "confirm", "action": "send", "address": f"{address}", "id": f"{blockID}"}

    return response


async def updateVotingWeights():  # Updates the voting weights for all accounts which have been delegated to
    global votingWeights
    votingWeights = {}
    for account in os.listdir(ledgerDir):
        head = await getHead(account)
        try:
            representative = head["representative"]

        except KeyError:
            representative = account

        if representative in votingWeights:
            votingWeights[representative] += float(head["balance"])

        else:
            votingWeights[representative] = float(head["balance"])

    for node in nodes:
        try:
            nodes[node][2] = votingWeights[nodes[node][1]]

        except KeyError:  # No one has delegated voting weight to the node
            nodes[node][2] = 0


# Verifies that data was created by stated account
async def verifySignature(signature, publicKey, data):
    data = data.copy()
    data.pop("signature")
    data = json.dumps(data).encode()
    publicKey = publicKey[4:56] + "===="
    publicKey = base64.b32decode(publicKey.upper().encode())
    verifier = VerifyKey(publicKey)
    signature = (int(signature, 16)).to_bytes(64, byteorder="little")
    try:
        verifier.verify(data, signature)
        return True

    except BadSignatureError:
        return False


# Verify given block in dictionary accounts recursively
async def verifyBlock(accounts, block, usedAsPrevious=[], directory=ledgerDir):
    logging.debug(f"Verifying block: {block}")
    if accounts[block["address"]][block["id"]][1]:
        return True

    if block["id"] in force_valid_blocks:
        accounts[block["address"]][block["id"]][1] = True
        return True

    # I need to clarify why this isn't "if not". "not None" returns True, but in this case I'm using the value None to represent a block which has no status yet and False to represent a block which has been rejected
    if accounts[block["address"]][block["id"]][1] == False:
        return False

    # check if previous block is already cited as previous by another block
    if (block["address"] + "/" + block["previous"]) in usedAsPrevious:
        accounts[block["address"]][block["id"]][1] = False
        logging.debug("previous already used (double spend)")
        return False

    # verify signature
    validSig = await verifySignature(block["signature"], block["address"], block)
    if not validSig:
        accounts[block["address"]][block["id"]][1] = False
        logging.debug("invalid signature")
        return False

    if block["type"] != "open" and block["type"] != "genesis":
        prevBlock = await getBlock(block["address"], block["previous"], directory=directory)

    # if send block, verify previous block balance is more than current balance
    if block["type"] == "send":
        if float(prevBlock["balance"]) < float(block["balance"]):
            accounts[block["address"]][block["id"]][1] = False
            logging.debug("New balance is too large (stealing send)")
            return False

    # if receive/open block, calculate the send amount and check if the new balance matches
    if block["type"] in ["receive", "open"]:
        sendBlock = await getBlock(block["link"].split("/")[0], block["link"].split("/")[1], directory=directory)
        sendPrevious = await getBlock(sendBlock["address"], sendBlock["previous"], directory=directory)
        sendAmount = float(sendPrevious["balance"]) - float(sendBlock["balance"])

        previousBalance = 0
        if block["type"] == "receive":
            previousBalance = float(prevBlock["balance"])

        if block["balance"] != previousBalance + sendAmount:
            accounts[block["address"]][block["id"]][1] = False
            logging.debug("new balance mismatch (received incorrect amount)")
            return False

        if not await verifyBlock(accounts, sendBlock, usedAsPrevious, directory=directory):
            accounts[block["address"]][block["id"]][1] = False
            logging.debug("invalid send block")
            return False

    if block["type"] == "genesis":
        if block["signature"] != "0xbc9accb157a6c23403cc6f7d5be7f4ef77e04a38517a2105719eb1ad784ebee2479f128403e5a826b82c150ca48ce548009c9bc529f649f63dd104bd140951a":
            accounts[block["address"]][block["id"]][1] = False
            logging.warning("FAKE GENESIS DETECTED, our ledger is completely invalid.")
            return False

    if block["type"] == "open":
        accounts[block["address"]][block["id"]][1] = True
        logging.debug("Open Block Verified")
        return True

    if block["type"] == "genesis":
        accounts[block["address"]][block["id"]][1] = True
        logging.debug("Genesis Block Verified")
        return True

    if await verifyBlock(accounts, prevBlock, usedAsPrevious, directory=directory):
        accounts[block["address"]][block["id"]][1] = True
        logging.debug("Block Verified")
        toReturn = True

    else:
        accounts[block["address"]][block["id"]][1] = False
        logging.debug("Previous block is invalid")
        toReturn = False

    usedAsPrevious.append(block["address"] + "/" + prevBlock["id"])
    return toReturn


# Verifies EVERY transaction in the ledger (should probably only be called after downloading the ledger)
async def verifyLedger(directory):
    accounts = {}
    accountsDir = os.listdir(directory)
    for account in accountsDir:
        f = await aiofiles.open(directory + account)
        data = await f.read()
        await f.close()

        blocks = {}
        data = data.splitlines()
        for block in data:
            block = json.loads(block)
            blocks[block["id"]] = [block, None]

        accounts[account] = blocks

    accountNames = accounts.keys()
    for accountName in accountNames:
        for block in accounts[accountName]:
            block = accounts[accountName][block][0]
            if accounts[accountName][block["id"]][1] == None:
                await verifyBlock(accounts, block, directory=directory)

    accountNames = accounts.keys()
    for accountName in accountNames:
        for block in accounts[accountName]:
            if not accounts[accountName][block][1]:
                logging.error(f"One of the blocks in our ledger is invalid! {accountName}/{block}")
                return False

    logging.info("Ledger Verified!")
    return True


async def vote(data, **kwargs):
    """ Called when receiving a vote.
        1 - Validates block.
        2 - Adds to local vote pool, even if invalid.
        3 - Transmit my vote to all nodes I am in contact with."""

    valid = await verifySignature(data["signature"], data["address"], data)
    if not valid:
        return json.dumps({"type": "rejection", "action": "vote", "reason": "signature"})

    for node in nodes:
        if nodes[node][1] == data["address"]:
            weight = nodes[node][2]
            break

    if data["vote"] == "against":
        weight *= -1

    logging.debug(f"VoteID: { data['voteID']}")
    logging.debug(votePool.keys())
    logging.debug(data["voteID"] in votePool)
    if data["voteID"] in votePool:  # Vote is already in pool so just update
        for ballot in votePool[data["voteID"]][3]:
            if data["address"] == ballot[0]["address"]:  # Address has already voted
                {"type": "rejection", "action": "vote", "reason": "double vote"}

        votePool[data["voteID"]][1] += weight
        votePool[data["voteID"]][3].append([data, weight])
        if votePool[data["voteID"]][1] >= votePool[data["voteID"]][0] and not votePool[data["voteID"]][4]:
            logging.debug("Consensus reached: " + str(votePool[data["voteID"]]))
            if data["block"]["type"] != "open":
                f = await aiofiles.open(f"{ledgerDir}{json.loads(data['block'])['address']}", "a")
                await f.write("\n" + data["block"])
                await f.close()
            else:
                f = await aiofiles.open(f"{ledgerDir}{json.loads(data['block'])['address']}", "w+")
                await f.write(data["block"])
                await f.close()
            votePool[data["voteID"]][4] = True

        return {"type": "confirm", "action": "vote"}

    offline = False if len(nodes) == 0 else True  # If nodes are connected but none are responsive, reboot
    onlineWeight = 0
    for node in nodes:
        ws = nodes[node][0]
        try:
            await ws.send('{"type": "ping"}')
            resp = await ws.recv()
            offline = False
            if json.loads(resp)["type"] == "confirm":
                logging.debug("Node available to receive vote", node)

        except Exception as e:
            logging.info("Error while contacting node for vote: " + str(e))
            nodes.pop(node)
            pass
        onlineWeight += nodes[node][2]
        
    if offline:
        await asyncio.sleep(60)
        os.execv(sys.argv[0], sys.argv)

    votePool[data["voteID"]] = [onlineWeight * CONSENSUS_PERCENT, weight, json.loads(data["block"]), [[data, weight]], False]
    if votePool[data["voteID"]][1] >= votePool[data["voteID"]][0] and not votePool[data["voteID"]][4]:
        logging.debug("Consensus reached: " + str(votePool[data["voteID"]]))
        f = await aiofiles.open(f"{ledgerDir}{json.loads(data['block'])['address']}", "a")
        await f.write("\n" + data["block"])
        await f.close()
        votePool[data["voteID"]][4] = True

    for ballot in votePool[data["voteID"]][3]:
        if publicKeyStr == ballot[0]["address"]:  # Our address has already voted so do not cast a vote
            return {"type": "confirm", "action": "vote"}

    blockType = json.loads(data["block"])["type"]
    block = json.loads(data["block"])

    if block["address"] in lockedAddresses:
        resp = {"type": "rejection", "reason": "This address has a pending transaction.",
                    "latest_unlock_time": lockedAddresses[data["address"]]}

    elif blockType == "send":
        resp = await send(block)

    elif blockType == "receive":
        resp = await receive(block)

    elif blockType == "open":
        resp = await openAccount(block)

    elif blockType == "change":
        resp = await change(block)

    else:
        logging.debug(f"Incoming vote block is of unknown type: {data['block']}")
        resp = {"type": "rejection"}

    if resp["type"] == "confirm":
        valid = True
        logging.debug(f"Incoming vote block is valid: {data['block']}")

    else:
        valid = False
        logging.debug(f"Incoming vote block is invalid: {data['block']}")
        logging.debug(resp)

    if valid:
        lockedAddresses[data["address"]] = int(time.time()) + BLOCK_TIMEOUT
        task = asyncio.create_task(unlock_address(data["address"], BLOCK_TIMEOUT))
        background_tasks.add(task)
        task.add_done_callback(background_tasks.discard)
        forAgainst = "for"

    else:
        forAgainst = "against"

    packet = {"type": "vote", "voteID": data['voteID'], "vote": forAgainst, "block": data['block'], "address": publicKeyStr}
    signature = await genSignature(packet, privateKey)
    packet["signature"] = signature

    votePool[data["voteID"]][1] += float(votingWeights[publicKeyStr])
    votePool[data["voteID"]][3].append([packet, votingWeights[publicKeyStr]])

    if votePool[data["voteID"]][1] >= votePool[data["voteID"]][0] and not votePool[data["voteID"]][4]:
        logging.debug("Consensus reached: " + str(votePool[data["voteID"]]))
        f = await aiofiles.open(f"{ledgerDir}{json.loads(data['block'])['address']}", "a")
        await f.write("\n" + data["block"])
        await f.close()
        votePool[data["voteID"]][4] = True
        lockedAddresses.pop(data["address"])

    validNodesStr = ""
    validNodes = []
    for node in nodes:
        ws = nodes[node][0]
        try:
            await ws.send('{"type": "ping"}')
            resp = await ws.recv()
            if json.loads(resp)["type"] == "confirm":
                logging.debug("Available", node)
                validNodesStr = validNodesStr + "|" + node
                validNodes.append(node)

        except Exception as e:
            logging.debug("Error: " + str(e))
            pass

    for node in validNodes:
        await nodes[node][0].send(json.dumps(packet))
        resp = await ws.recv()
        try:
            resp = json.loads(resp)
            if resp["type"] != "confirm":
                raise Exception(f"Invalid response: {json.dumps(resp)}")

            logging.debug("Vote received by ", node)

        except TimeoutError:
            logging.debug("Vote not received by ", node)

        except Exception as e:
            logging.debug(f"Exception while receiving vote confirmation from {node}")
            logging.debug(e)

    return {"type": "confirm", "action": "vote"}


async def getAccounts(data, ws):
    """ Get a list of all accounts that have been opened, along with their balance """
    accountsDir = os.listdir(ledgerDir)
    accounts = {}
    for account in accountsDir:
        head = await getHead(account)
        accounts[account] = head["balance"]
        
    response = {"type": "getAccounts", "accounts": accounts}
    return response

async def getTransactions(data, ws):
    """Get a list of all transactions made by an account"""
    address = data["address"]
    transactions = []
    try:
        with open(f"{ledgerDir}{address}", "r") as f:
            for line in f:
                transactions.append(json.loads(line))

    except FileNotFoundError:
        return {"type": "getTransactions", "transactions": [], "softError": "addressNonExistent"}
    
    response = {"type": "getTransactions", "transactions": transactions}
    return response
    

async def watchForSends(data, ws):
    """ Allows a connection to receive notifications when a given address is sent new MXC.
        Not persistently stored, needs to be re-called if node restarts."""

    global sendSubscriptions
    address = data["address"]

    try:
        prevSubs = sendSubscriptions[address]

    except KeyError:
        prevSubs = []

    prevSubs.append(ws)
    sendSubscriptions[address] = prevSubs

    resp = {"type": "confirm", "action": "watchForSends", "address": address}
    return resp


requestFunctions = {"balance": balance, "pendingSend": checkForPendingSend, "getPrevious": getPrevious, "watchForSends": watchForSends, "getRepresentative": getRepresentative, "getAccounts": getAccounts, "getBlock": getBlockRequest, "getHead": getHeadRequest, "getTransactions": getTransactions, # Relates to accounts
                    "registerNode": registerNode, "fetchNodes": fetchNodes, "ping": ping, "vote": vote,  # Relates to nodes
                    "receive": initiate, "open": initiate, "send": initiate, "change": initiate}  # Relates to starting transactions


# Handles incoming websocket connections
async def incoming(websocket, path):
    global nodes
    logging.debug(f"Client handshake started with {websocket.remote_address[0]}")

    recipientKey = await websocket.recv()
    recipientKey = RSA.import_key(recipientKey)
    session_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(recipientKey)
    enc_session_key = cipher_rsa.encrypt(session_key)
    global sessionKeys
    #sessionKey = enc_session_key.hex()
    sessionKey = base64.b64encode(enc_session_key).decode("utf-8")
    sessionKeys[websocket] = session_key
    await websocket.send(json.dumps({"type": "sessionKey", "sessionKey": sessionKey}))

    logging.info(f"Client Connected: {websocket.remote_address[0]}")
    while True:
        try:
            data = await websocket.recv()
            ciphertext, tag, nonce = data.split("|||")
            ciphertext, tag, nonce = base64.b64decode(ciphertext.encode("utf-8")), base64.b64decode(tag.encode("utf-8")), base64.b64decode(nonce.encode("utf-8"))
            cipher_aes = AES.new(session_key, AES.MODE_GCM, nonce)
            plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)
            data = plaintext.decode("utf-8")
            data = ''.join(c for c in data if c.isprintable())
            logging.debug(repr(data))

        except websockets.exceptions.ConnectionClosedOK:
            logging.info(f"Client Disconnected: {websocket.remote_address[0]}")
            break
        except Exception as e:
            logging.info(f"Client Disconnected: {websocket.remote_address[0]}")
            logging.debug(traceback.format_exc())
            break

        data = json.loads(data)
        logging.info(f"Received Data from {websocket.remote_address[0]}: {data}")

        if data["type"] in requestFunctions:
            try:
                response = await requestFunctions[data["type"]](data=data, ws=websocket)
            
            except Exception as e:
                logging.debug(traceback.format_exc())
                response = {"type": "rejection", "reason": "internal server error"}

        else:
            response = {"type": "rejection", "reason": "unknown request"}

        logging.info(f"Responding to {websocket.remote_address[0]}: {response}")

        response = json.dumps(response)
        cipher_aes = AES.new(session_key, AES.MODE_GCM)
        ciphertext, tag = cipher_aes.encrypt_and_digest(response.encode("utf-8"))
        await websocket.send(base64.b64encode(ciphertext).decode("utf-8") + "|||" + base64.b64encode(tag).decode("utf-8") + "|||" + base64.b64encode(cipher_aes.nonce).decode("utf-8"))


# Handles incoming ledger requests
async def ledgerServer(websocket, url):
    logging.info(f"Ledger Requested by {websocket.remote_address[0]}")
    for account in os.listdir(ledgerDir):
        await websocket.send(f"Account:{account}")
        f = await aiofiles.open(ledgerDir + account)
        toSend = await f.read()
        await f.close()
        for line in toSend.splitlines():
            await websocket.send(line)

    await websocket.send("ayothatsall")


async def bootstrap():
    # 1 - Get a dictionary of current account heads
    # 2 - Ask top 20 nodes for their account heads
    # 3 - Choose set of heads with most voting weight
    # 4 - Download all transactions since our heads
    # 5 - Verify those transactions locally
    # 6 - If valid, overwrite stored ledger
    # 7 - If not valid, download from another node

    try:
        shutil.rmtree(bootstrapDir)
    except FileNotFoundError:
        pass

    await copytree(ledgerDir, bootstrapDir)

    heads = {}  # Dictionary of account - head_ID mappings
    logging.debug(f"Existing ledger contents: {os.listdir(ledgerDir)}")
    logging.debug(f"Current Working Directory: {os.getcwd()}")
    for account in os.listdir(ledgerDir):  # Iterate through all stored accounts
        head = await getHead(account)
        heads[account] = head["id"]

    newHeads = {}
    logging.debug(f"Nodes: {nodes}")
    sortedWeights = reversed(dict(sorted(nodes.items(), key=lambda item: item[1][2])))  # Get a sorted dictionary of ip - weight mappings
    count = 0
    for node in sortedWeights:
        if count >= 20:  # Only get heads from top 20 nodes so it's faster
            break

        count += 1

        _, node, port = node.split(":")
        node = f"ws:{node}:{int(port)+1}"  # Get node's bootstrap address
        ws = await websocketSecure.connect(node)
        request = {"type": "getHeads"}
        await ws.send(json.dumps(request))  # Ask node to start sending over their heads

        resp = ""
        nodeHeads = {}
        end = json.dumps({"type": "endHeadsTransmission"})
        while resp != end:  # Can only receive 320 account heads per message
            resp = await ws.recv()
            accounts = resp.split("/")
            for account in accounts:
                try:
                    accountAddress, head = account.split("+")

                except ValueError:  # End of transmission
                    pass
                nodeHeads[accountAddress] = head  # Add each account's head to nodeHeads

        newHeads[node] = nodeHeads  # Add each node's heads to newHeads
        await ws.close()

    combinedHeads = []
    for node in newHeads:  # Combine submitted heads
        _, nodeOriginal, port = node.split(":")
        nodeOriginal = f"ws:{nodeOriginal}:{int(port)-1}"
        nodeHeads = newHeads[node]  # Get current node's submitted heads
        combined = False  # Assume nodeHeads is not already in combinedHeads
        for i in range(len(combinedHeads)):  # Iterate through combinedHeads
            if nodeHeads == combinedHeads[i][0]:  # If nodeHeads in combinedHeads
                combinedHeads[i][1] += nodes[nodeOriginal][1][2]  # Add node's voting weight to the existing heads
                combined = True  # nodeHeads is already in combined heads
                break  # No need to continue searching

        if not combined:  # If nodeHeads not already in combinedHeads
            combinedHeads.append([newHeads[node], nodes[nodeOriginal][1][2]])  # Add to combinedHeads

    combinedHeads = sorted(combinedHeads, key=lambda item: item[1])
    chosenHeads = combinedHeads[-1][0]  # Find most voted set of heads

    possibleNodes = []   # List of nodes who provided the chosen heads
    for node in newHeads:
        logging.debug(newHeads[node])
        if newHeads[node] == chosenHeads:
            possibleNodes.append(node)

    valid = False
    while not valid:
        if len(possibleNodes) <= 0:
            logging.warning("While bootstrapping, all available nodes returned invalid ledgers. Something has gone seriously wrong.")
            sys.exit()

        node = random.choice(possibleNodes)

        ws = await websocketSecure.connect(node)
        for account in chosenHeads:
            if account not in heads or heads[account] != chosenHeads[account]:  # If we don't have that account, or it has been updated
                try:
                    ourHead = heads[account]

                except KeyError:  # If we do not have the account, fetch entire account
                    ourHead = ""

                req = {"type": "requestAccount", "head": ourHead, "address": account}
                await ws.send(json.dumps(req))
                blocks = ""
                resp = ""
                end = json.dumps({"type": "endAccountTransmission"})
                while resp != end:
                    resp = await ws.recv()
                    blocks = blocks + resp + "\n"

                blocks = blocks.replace('{"type": "endAccountTransmission"}', '')
                blocks = blocks.strip()
                if ourHead != "":
                    blocks = "\n" + blocks

                f = await aiofiles.open(bootstrapDir+account, "a+")
                await f.write(blocks)
                await f.close()

        valid = await verifyLedger(bootstrapDir)
        possibleNodes.pop(possibleNodes.index(node))
        await ws.close()

    await copytree(bootstrapDir, ledgerDir)
    shutil.rmtree(bootstrapDir)


# Check if node running on given url
async def testWebsocket(url):
    try:
        async def wait_for_this(url):
            try:
                websocket = await websocketSecure.connect(url)
            except TimeoutError:
                return False
            
            await websocket.send('{"type": "ping"}')
            await websocket.recv()
            await websocket.close()

            return True

        return await asyncio.wait_for(wait_for_this(url), 3)

    except:
        return False


# Starts the node
async def run():
    global ip
    global myPort
    # Get my public IP
    async with aiohttp.ClientSession() as session:
        async with session.get('https://api.ipify.org') as response:
            ip = await response.text()

    print("Verifying ledger... May take a while")
    print(f"Ledger verified {await verifyLedger(ledgerDir)}")

    await updateVotingWeights()

    if await testWebsocket(f"ws://{ip}:6969"):
        # A node already exists on our network, so boot on the secondary port
        await websockets.serve(incoming, "0.0.0.0", 5858)
        logging.info("A node already exists on our network on port 6969, so running on port 5858 instead.")
        myPort = 5858
        entrypoints.append(f"ws://{ip}:6969")


    else:
        # No other nodes exist on our network, so boot on the primary port
        await websockets.serve(incoming, "0.0.0.0", 6969)
        myPort = 6969

    for node in entrypoints:
        logging.debug(f"Testing entrypoint: {node}")
        if not await testWebsocket(node):
            logging.info(f"Entrypoint not available: {node}")
            continue

        nodeIP = node.replace("ws://", "").split(":")[0]
        nodePort = node.replace("ws://", "").split(":")[1]
        nodeIP = socket.gethostbyname(nodeIP)
        isLocalMachine = (nodeIP == "localhost" or nodeIP == "127.0.0.1" or nodeIP == ip) and str(myPort) == str(node.split(":")[2])
        if isLocalMachine:
            logging.debug(f"Ignoring entrypoint, because it's me.")
            continue

        logging.info(f"Registering with {node}")
        await registerMyself(f"ws://{nodeIP}:{nodePort}", doRespond=True)


    logging.info(f"Booting on {ip}:{myPort}")
    await websockets.serve(bootstrap_server, "0.0.0.0", myPort+1)
    if len(nodes) != 0:
        await bootstrap()
        await updateVotingWeights()

    await asyncio.Event().wait()

if __name__ == "__main__":
    asyncio.run(run())

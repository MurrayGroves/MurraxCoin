import asyncio
import json
import aiofiles

import websockets
import aiohttp
import socket

import os
import random
import traceback

from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

# Configuration Variables
entrypoints = ["ws://qwhwdauhdasht.ddns.net:6969", "ws://murraxcoin.murraygrov.es:6969"]  # List of known nodes that can be used to "enter" the network.
ledgerDir = "Accounts/"  # Path to the directory where the ledger will be stored (must end in /)
publicFile = "../public_key.pem"  # Path of the node's public key
privateFile = "../private_key.pem"  # Path of the node's private key
consensusPercent = 0.65  # Float representing what percent of the online voting nodes must agree with a transaction for it to be confirmed.

# Import node's private key
f = open(privateFile, "rt")
privateKey = ECC.import_key(f.read())
f.close()

# Import node's public key
f = open(publicFile, "rt")
publicKey = ECC.import_key(f.read())
f.close()

# Get a nicer representation of the public key
publicKeyStr = publicKey.export_key(format="PEM", compress=True)
publicKeyStr = publicKeyStr.replace("-----BEGIN PUBLIC KEY-----\n", "")
publicKeyStr = publicKeyStr.replace("\n-----END PUBLIC KEY-----", "")
publicKeyStr = publicKeyStr.replace("\n", " ")

# Create the ledger directory
os.makedirs(ledgerDir, exist_ok=True)

# Initialise global variables
nodes = {}  # Dictionary of all connected nodes. Structure follows:
            #   {ip : websocket}
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

ip = -1
myPort = -1

votingWeights = {}

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


class websocketSecure:
    def __init__(self, url):
        self.url = url

    async def initiateConnection(self):
        self.websocket = await websockets.connect(self.url)
        await self.websocket.send(handshakePublicKeyStr)
        handshakeData = await self.websocket.recv()
        print("Data: " + handshakeData)
        handshakeData = json.loads(handshakeData)

        sessionKey = bytes.fromhex(handshakeData["sessionKey"])
        self.sessionKey = handshakeCipher.decrypt(sessionKey)

    @classmethod
    async def connect(cls, url):
        self = websocketSecure(url)
        await asyncio.wait({self.initiateConnection()})
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
        ciphertext, tag, nonce = bytes.fromhex(ciphertext), bytes.fromhex(tag), bytes.fromhex(nonce)
        cipher = AES.new(self.sessionKey, AES.MODE_EAX, nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        plaintext = plaintext.decode("utf-8")

        return plaintext

    async def send(self, plaintext):
        cipher = AES.new(self.sessionKey, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
        await self.websocket.send(ciphertext.hex() + "|||" + tag.hex() + "|||" + cipher.nonce.hex())

    async def close(self):
        await self.websocket.close()


async def balance(data: dict, **kwargs) -> str:
    """Returns an account's balance"""

    address = data["address"]

    try:
        block = await getHead(address)

    except FileNotFoundError:
        response = f'{{"type": "rejection", "address": "{address}", "reason": "addressNonExistent"}}'
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
                print("Available", node)
                validNodesStr = validNodesStr + "|" + node
                validNodes.append(node)

        except Exception as e:
            print("Error: " + str(e))
            pass

    packet = {"type": "vote", "voteID": broadcastID, "vote": "for", "block": json.dumps(data), "address": publicKeyStr}
    signature = await genSignature(packet, privateKey)
    print(signature)
    print("Broadcast: " + json.dumps(packet))
    packet["signature"] = signature

    weight = await balance({"address": publicKeyStr})
    weight = float(json.loads(weight)["balance"])

    onlineWeight = 0
    for node in nodes:
        onlineWeight += nodes[node][2]

    votePool[broadcastID] = [onlineWeight*consensusPercent, weight, data, [[packet, weight]], False]
    if votePool[broadcastID][1] >= votePool[broadcastID][0]:
        print("Consensus reached: " + str(votePool[broadcastID]))
        if data["type"] != "open":
            f = await aiofiles.open(f"{ledgerDir}{data['address']}", "a")
            await f.write("\n" + json.dumps(data))
            await f.close()
        else:
            f = await aiofiles.open(f"{ledgerDir}{data['address']}", "w+")
            await f.write(json.dumps(data))
            await f.close()

        votePool[broadcastID][4] = True

    for node in validNodes:
        await nodes[node][0].send(json.dumps(packet))
        resp = await ws.recv()
        try:
            resp = json.loads(resp)
            if resp["type"] != "confirm":
                raise Exception(f"Invalid response: {json.dumps(resp)}")

            print("Vote received by ", node)

        except TimeoutError:
            print("Vote not received by ", node)

        except Exception as e:
            print("Exception while receiving vote confirmation")
            print(e)


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
                    resp = json.dumps(resp)
                    return resp

    response = {"type": "pendingSend", "link": "", "sendAmount": ""}
    return response


async def change(data, **kwargs):
    signature = data["signature"]
    address = data["address"]
    blockID = data["id"]

    valid = await verifySignature(signature, address, data)
    if not valid:
        toRespond = f'{{"type": "rejection", "address": "{address}", "id": "{blockID}", "reason": "signature"}}'
        return toRespond

    previousBlock = await getBlock(address, data["previous"])
    # Check that balance has not changed
    if float(data["balance"]) != float(previousBlock["balance"]):
        toRespond = f'{{"type": "rejection", "address": "{address}", "id": "{blockID}", "reason": "balance"}}'
        return toRespond

    if data["representative"] not in os.listdir(ledgerDir):  # If account to be delegated to does not exist
        toRespond = f'{{"type": "rejection", "address": "{address}", "id": "{blockID}", "reason": "link"}}'
        return toRespond

    toRespond = {"type": "confirm", "action":"delegate","address": address, "id": blockID}
    return toRespond


# Return a list of available nodes
async def fetchNodes(**kwargs):
    global nodes
    nodeAddresses = ""
    for node in nodes:
        nodeAddresses = nodeAddresses + "|" + node

    response = {"type": "confirm", "action": "fetchNodes", "nodes": nodeAddresses}
    return response


async def genSignature(data, privateKey):
    """ Sign data with private key"""

    data = json.dumps(data)
    signer = DSS.new(privateKey, "deterministic-rfc6979")
    signatureHash = SHA256.new()
    signatureHash.update(data.encode("utf-8"))
    signature = signer.sign(signatureHash)
    signature = hex(int.from_bytes(signature, "little"))

    return signature


# Return a block belonging to the account (address) with block ID (blockID)
async def getBlock(address, blockID):
    f = await aiofiles.open(f"{ledgerDir}{address}")
    fileStr = await f.read()
    await f.close()
    fileStr = fileStr.splitlines()

    blocks = []
    for block in fileStr:
        print(block)
        blocks.append(json.loads(block))

    for block in blocks:
        if block["id"] == blockID:
            return block

    print("not found")


async def getPrevious(data, **kwargs):
    head = await getHead(data["address"])
    address = data["address"]
    previous = head["id"]
    response = {"type": "previous", "address": address, "link": previous}
    return response


async def getRepresentative(address, **kwargs):  # Get address of an account's representative
    head = await getHead(address)
    try:
        representative = head["representative"]

    except KeyError:
        representative = address

    return {"type": "info", "address": address, "representative": representative}


# Get the head block of an account (the most recent block)
async def getHead(address, **kwargs):
    f = await aiofiles.open(f"{ledgerDir}{address}")
    fileStr = await f.read()
    await f.close()
    fileStr = fileStr.splitlines()

    blocks = []
    for block in fileStr:
        blocks.append(json.loads(block))

    if len(blocks) == 1:
        return blocks[0]

    # Sort blocks in order
    isSorted = False
    while not isSorted:
        isSorted = True
        for i in range(1, len(blocks)):
            previous = blocks[i]["previous"]
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


async def initiate(data, **kwargs):
    if data["type"] == "change":
        response = await change(data)

    elif data["type"] == "open":
        response = await openAccount(data)

    elif data["type"] == "receive":
        response = await receive(data)

    else:
        response = await send(data)

    if response["type"] == "confirm":
        await broadcast(data)

    return response


# Process an open transaction
async def openAccount(data):
    signature = data["signature"]
    address = data["address"]
    blockID = data["id"]

    valid = await verifySignature(signature, address, data)
    if not valid:
        toRespond = {"type": "rejection", "address": "{address}", "id": "{blockID}", "reason": "signature"}
        return toRespond

    sendingAddress, sendingBlock = data["link"].split("/")
    sendingBlock = await getBlock(sendingAddress, sendingBlock)

    # Check that send block is valid
    valid = await verifySignature(sendingBlock["signature"], sendingAddress, sendingBlock)
    if not valid:
        toRespond = {"type": "rejection", "address": "{address}", "id": "{blockID}", "reason": "sendSignature"}
        return toRespond

    previousBlock = await getBlock(sendingAddress, sendingBlock["previous"])
    sendAmount = float(previousBlock["balance"]) - float(sendingBlock["balance"])

    if float(data["balance"]) != float(sendAmount):
        response = {"type": "rejection", "address": "{address}", "id": "{blockID}", "reason": "invalidBalance"}

    elif data["previous"] != "0"*20:
        response = {"type": "rejection", "address": "{address}", "id": "{blockID}", "reason": "invalidPrevious"}

    else:
        response = {"type": "confirm", "action": "open","address": "{address}", "id": "{blockID}"}

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
        toRespond = {"type": "rejection", "address": "{address}", "id": "{blockID}", "reason": "signature"}
        return toRespond

    sendingAddress, sendingBlock = data["link"].split("/")
    sendingBlock = await getBlock(sendingAddress, sendingBlock)

    # Check that send block is valid
    valid = await verifySignature(sendingBlock["signature"], sendingAddress, sendingBlock)
    if not valid:
        toRespond = {"type": "rejection", "address": "{address}", "id": "{blockID}", "reason": "sendSignature"}
        return toRespond

    f = await aiofiles.open(f"{ledgerDir}{address}")
    blocks = await f.read()
    await f.close()
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
        response = {"type": "rejection", "address": "{address}", "id": "{blockID}", "reason": "invalidBalance"}

    elif data["previous"] != head["id"]:
        response = {"type": "rejection", "address": "{address}", "id": "{blockID}", "reason": "invalidPrevious"}

    else:
        response = {"type": "confirm", "action":"receive","address": "{address}", "id": "{blockID}"}

    return response


# Register myself with specified node
async def registerMyself(node, doRespond):
    global myPort
    global ip
    print(f"Registering with {node}")
    websocket = await websocketSecure.connect(node)
    await websocket.send(f'{{"type": "registerNode", "port": "{myPort}", "address": "{publicKeyStr}","respond": "{str(doRespond)}"}}')
    resp = await websocket.recv()
    if json.loads(resp)["type"] == "confirm":
        print(f"Node registered with: {node}")
        global nodes
        nodes[node][0] = websocket

        await websocket.send('{"type": "fetchNodes"}')
        newNodes = await websocket.recv()
        print(newNodes)
        newNodes = json.loads(newNodes)["nodes"].split("|")[1:]
        print(newNodes)
        for node in newNodes:
            nodeIP = node.replace("ws://", "").split(":")[0]
            print(nodeIP)
            print(myPort)
            print(node.split(":")[2])
            isLocalMachine = (nodeIP == "localhost" or nodeIP == "127.0.0.1" or nodeIP == ip) and str(myPort) == str(node.split(":")[2])
            if node not in nodes and not isLocalMachine:
                await registerMyself(node, doRespond=True)

    else:
        await websocket.close()
        print(f"Failed to register with: {node}")

    print("Done registering")


async def registerNode(data, websocket):
    response = {"type": "confirm", "action": "registerNode"}
    try:
        weight = float(votingWeights[data["address"]])

    except KeyError:  # No one has delegated the node's address
        weight = 0

    nodes[f"ws://{websocket.remote_address[0]}:{data['port']}"] = [None, data["address"], weight]
    if data["respond"] == "True":
        await registerMyself(f"ws://{websocket.remote_address[0]}:{data['port']}", doRespond=False)

    return response


# Processes a send transaction
async def send(data):
    signature = data["signature"]
    address = data["address"]
    blockID = data["id"]

    valid = await verifySignature(signature, address, data)
    if not valid:
        response = {"type": "rejection", "address": "{address}", "id": "{blockID}", "reason": "signature"}

    head = await getHead(address)
    if float(head["balance"]) < float(data["balance"]):
        response = {"type": "rejection", "address": "{address}", "id": "{blockID}", "reason": "balance"}

    elif head["id"] != data["previous"]:
        response = {"type": "rejection", "address": "{address}", "id": "{blockID}", "reason": "invalidPrevious"}

    else:
        response = {"type": "confirm", "action": "send", "address": "{address}", "id": "{blockID}"}

    if response["type"] != "confirm":
        return response

    if data["link"] in sendSubscriptions:
        sendAlert = {"type": "sendAlert", "address": data["link"],
                     "sendAmount": str(float(head["balance"]) - float(data["balance"])),
                     "link": f"{address}/{blockID}"}

        sendAlert = json.dumps(sendAlert)
        for ws in sendSubscriptions[data["link"]]:
            try:
                await ws.send(sendAlert)

            except websockets.exceptions.ConnectionClosedError:
                pass

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
    data = json.dumps(data)
    publicKey = publicKey.split(" ")
    publicKey = "-----BEGIN PUBLIC KEY-----\n" + publicKey[0] + "\n" + publicKey[1] + "\n-----END PUBLIC KEY-----"
    publicKey = ECC.import_key(publicKey)
    signature = (int(signature, 16)).to_bytes(64, byteorder="little")
    data = SHA256.new(data.encode("utf-8"))
    verifier = DSS.new(publicKey, "fips-186-3")
    try:
        verifier.verify(data, signature)
        return True

    except ValueError:
        return False


# Verify given block in dictionary accounts recursively
async def verifyBlock(accounts, block, usedAsPrevious=[]):
    if accounts[block["address"]][block["id"]][1]:
        return True

    # I need to clarify why this isn't "if not". "not None" returns True, but in this case I'm using the value None to represent a block which has no status yet and False to represent a block which has been rejected
    if accounts[block["address"]][block["id"]][1] == False:
        return False

    # check if previous block is already cited as previous by another block
    if (block["address"] + "/" + block["previous"]) in usedAsPrevious:
        accounts[block["address"]][block["id"]][1] = False
        print("previous already used")
        return False

    # verify signature
    validSig = await verifySignature(block["signature"], block["address"], block)
    if not validSig:
        accounts[block["address"]][block["id"]][1] = False
        print("invalid signature")
        return False

    if block["type"] != "open" and block["type"] != "genesis":
        prevBlock = await getBlock(block["address"], block["previous"])

    # if send block, verify previous block balance is more than current balance
    if block["type"] == "send":
        if float(prevBlock["balance"]) < float(block["balance"]):
            accounts[block["address"]][block["id"]][1] = False
            print("New balance is too large")
            return False

    # if receive/open block, calculate the send amount and check if the new balance matches
    if block["type"] in ["receive", "open"]:
        sendBlock = await getBlock(block["link"].split("/")[0], block["link"].split("/")[1])
        sendPrevious = await getBlock(sendBlock["address"], sendBlock["previous"])
        sendAmount = float(sendPrevious["balance"]) - float(sendBlock["balance"])

        previousBalance = 0
        if block["type"] == "receive":
            previousBalance = float(prevBlock["balance"])

        if block["balance"] != previousBalance + sendAmount:
            accounts[block["address"]][block["id"]][1] = False
            print("new balance mismatch")
            return False

        if not await verifyBlock(accounts, sendBlock, usedAsPrevious):
            accounts[block["address"]][block["id"]][1] = False
            print("invalid send block")
            return False

    if block["type"] == "genesis":
        if block["signature"] != "0xc9052f33ef7690bf24171ec5c4f506caeee1ab88419dc6abc0644e6033f6c526ccff87f6bc8096b0463e38e3221c054b88938408fbaada4a6148d46d38daa52b":
            accounts[block["address"]][block["id"]][1] = False
            print("FAKE GENESIS DETECTED")
            return False

    if block["type"] == "open":
        accounts[block["address"]][block["id"]][1] = True
        print("Open Block Verified")
        return True

    if block["type"] == "genesis":
        accounts[block["address"]][block["id"]][1] = True
        print("Genesis Block Verified")
        return True

    if await verifyBlock(accounts, prevBlock, usedAsPrevious):
        accounts[block["address"]][block["id"]][1] = True
        print("Block Verified")
        toReturn = True

    else:
        accounts[block["address"]][block["id"]][1] = False
        print("Previous block is invalid")
        toReturn = False

    usedAsPrevious.append(block["address"] + "/" + prevBlock["id"])
    return toReturn

# Verifies EVERY transaction in the ledger (should probably only be called after downloading the ledger)
async def verifyLedger():
    accounts = {}
    accountsDir = os.listdir(ledgerDir)
    for account in accountsDir:
        f = await aiofiles.open(ledgerDir + account)
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
                await verifyBlock(accounts, block)

    accountNames = accounts.keys()
    for accountName in accountNames:
        for block in accounts[accountName]:
            if not accounts[accountName][block][1]:
                print("BLOCK NOT VALID!!!!!")

    print("Ledger Verified!")


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

    print("VoteID: " + data["voteID"])
    print(votePool.keys())
    print(data["voteID"] in votePool)
    if data["voteID"] in votePool:  # Vote is already in pool so just update
        for ballot in votePool[data["voteID"]][3]:
            if data["address"] == ballot[0]["address"]:  # Address has already voted
                {"type": "rejection", "action": "vote", "reason": "double vote"}

        votePool[data["voteID"]][1] += weight
        votePool[data["voteID"]][3].append([data, weight])
        if votePool[data["voteID"]][1] >= votePool[data["voteID"]][0] and not votePool[data["voteID"]][4]:
            print("Consensus reached: " + str(votePool[data["voteID"]]))
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

    onlineWeight = 0
    for node in nodes:
        onlineWeight += nodes[node][2]

    votePool[data["voteID"]] = [onlineWeight * consensusPercent, weight, json.loads(data["block"]), [[data, weight]], False]
    if votePool[data["voteID"]][1] >= votePool[data["voteID"]][0] and not votePool[data["voteID"]][4]:
        print("Consensus reached: " + str(votePool[data["voteID"]]))
        f = await aiofiles.open(f"{ledgerDir}{json.loads(data['block'])['address']}", "a")
        await f.write("\n" + data["block"])
        await f.close()
        votePool[data["voteID"]][4] = True

    for ballot in votePool[data["voteID"]][3]:
        if publicKeyStr == ballot[0]["address"]:  # Our address has already voted so do not cast a vote
            return {"type": "confirm", "action": "vote"}

    blockType = json.loads(data["block"])["type"]
    if blockType == "send":
        resp = await send(data["block"])

    elif blockType == "receive":
        resp = await receive(data["block"])

    elif blockType == "open":
        resp = await openAccount(data["block"])

    elif blockType == "change":
        resp = await change(data["block"])

    else:
        print(f"Incoming vote block is of unknown type: {data['block']}")
        resp = {"type": "rejection"}

    if json.loads(resp)["type"] == "confirm":
        valid = True
        print(f"Incoming vote block is valid: {data['block']}")

    else:
        valid = False
        print(f"Incoming vote block is invalid: {data['block']}")

    if valid:
        forAgainst = "for"

    else:
        forAgainst = "against"

    packet = {"type": "vote", "voteID": data['voteID'], "vote": forAgainst, "block": data['block'], "address": publicKeyStr}
    signature = await genSignature(packet, privateKey)
    packet["signature"] = signature

    votePool[data["voteID"]][1] += float(votingWeights[publicKeyStr])
    votePool[data["voteID"]][3].append([packet, votingWeights[publicKeyStr]])

    if votePool[data["voteID"]][1] >= votePool[data["voteID"]][0] and not votePool[data["voteID"]][4]:
        print("Consensus reached: " + str(votePool[data["voteID"]]))
        f = await aiofiles.open(f"{ledgerDir}{json.loads(data['block'])['address']}", "a")
        await f.write("\n" + data["block"])
        await f.close()
        votePool[data["voteID"]][4] = True

    validNodesStr = ""
    validNodes = []
    for node in nodes:
        ws = nodes[node][0]
        try:
            await ws.send('{"type": "ping"}')
            resp = await ws.recv()
            if json.loads(resp)["type"] == "confirm":
                print("Available", node)
                validNodesStr = validNodesStr + "|" + node
                validNodes.append(node)

        except Exception as e:
            print("Error: " + str(e))
            pass

    for node in validNodes:
        await nodes[node][0].send(json.dumps(packet))
        resp = await ws.recv()
        try:
            resp = json.loads(resp)
            if resp["type"] != "confirm":
                raise Exception(f"Invalid response: {json.dumps(resp)}")

            print("Vote received by ", node)

        except TimeoutError:
            print("Vote not received by ", node)

        except Exception as e:
            print("Exception while receiving vote confirmation")
            print(e)

    return {"type": "confirm", "action": "vote"}


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


requestFunctions = {"balance": balance, "pendingSend": checkForPendingSend, "getPrevious": getPrevious, "watchForSends": watchForSends, "getRepresentative": getRepresentative,  # Relates to accounts
                    "registerNode": registerNode, "fetchNodes": fetchNodes, "ping": ping, "vote": vote,  # Relates to nodes
                    "receive": initiate, "open": initiate, "send": initiate, "change": initiate}  # Relates to starting transactions


# Handles incoming websocket connections
async def incoming(websocket, path):
    global nodes

    recipientKey = await websocket.recv()
    recipientKey = RSA.import_key(recipientKey)
    session_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(recipientKey)
    enc_session_key = cipher_rsa.encrypt(session_key)
    await websocket.send(json.dumps({"type": "sessionKey", "sessionKey": enc_session_key.hex()}))

    print(f"Client Connected: {websocket.remote_address[0]}")
    while True:
        try:
            data = await websocket.recv()
            ciphertext, tag, nonce = data.split("|||")
            ciphertext, tag, nonce = bytes.fromhex(ciphertext), bytes.fromhex(tag), bytes.fromhex(nonce)
            cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
            plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)
            data = plaintext.decode("utf-8")

        except:
            print("Client Disconnected")
            break

        data = json.loads(data)
        print(data)

        if data["type"] in requestFunctions:
            response = await requestFunctions[data["type"]](data=data, ws=websocket)

        else:
            response = {"type": "rejection", "reason": "unknown request"}

        response = json.dumps(response)
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(response.encode("utf-8"))
        await websocket.send(ciphertext.hex() + "|||" + tag.hex() + "|||" + cipher_aes.nonce.hex())


# Handles incoming ledger requests
async def ledgerServer(websocket, url):
    print("Ledger Requested")
    for account in os.listdir(ledgerDir):
        await websocket.send(f"Account:{account}")
        f = await aiofiles.open(ledgerDir + account)
        toSend = await f.read()
        await f.close()
        for line in toSend.splitlines():
            await websocket.send(line)

    await websocket.send("ayothatsall")


# Fetches the ledger from the specified node
async def fetchLedger(node):
    node = node.split(":")[0] + ":" + node.split(":")[1] + ":" + str(int(node.split(":")[2])+1)
    print(node)
    websocket = await websockets.connect(node)

    accounts = {}
    msg = await websocket.recv()
    while msg != "ayothatsall":
        curAccount = msg.replace("Account:", "")
        accounts[curAccount] = []
        msg = await websocket.recv()
        while "Account:" not in msg and "ayothatsall" not in msg:
            accounts[curAccount].append(msg)
            msg = await websocket.recv()

    for account in accounts:
        toWrite = ""
        for block in accounts[account]:
            toWrite = toWrite + "\n" + block

        toWrite = toWrite.replace("\n", "", 1)
        f = await aiofiles.open(ledgerDir + account, "w+")
        await f.write(toWrite)
        await f.close()


# Check if node running on given url
async def testWebsocket(url):
    try:
        websocket = await asyncio.wait_for(websocketSecure.connect(url), 3)
        await websocket.send('{"type": "ping"}')
        await websocket.recv()
        await websocket.close()

        return True

    except:
        traceback.print_exc()
        return False


# Starts the node
async def run():
    global ip
    global myPort
    # Get my public IP
    async with aiohttp.ClientSession() as session:
        async with session.get('https://api.ipify.org') as response:
            ip = await response.text()

    await updateVotingWeights()

    if await testWebsocket(f"ws://{ip}:6969"):
        # A node already exists on our network, so boot on the secondary port
        await websockets.serve(incoming, "0.0.0.0", 5858)
        print("running on secondary")
        myPort = 5858
        entrypoints.append(f"ws://{ip}:6969")
        global ledgerDir
        ledgerDir = "Accounts2/"

    else:
        # No other nodes exist on our network, so boot on the primary port
        await websockets.serve(incoming, "0.0.0.0", 6969)
        myPort = 6969

    for node in entrypoints:
        if not await testWebsocket(node):
            print(f"Node not available: {node}")
            continue

        nodeIP = node.replace("ws://", "").split(":")[0]
        nodePort = node.replace("ws://", "").split(":")[1]
        nodeIP = socket.gethostbyname(nodeIP)
        isLocalMachine = (nodeIP == "localhost" or nodeIP == "127.0.0.1" or nodeIP == ip) and str(myPort) == str(node.split(":")[2])
        if isLocalMachine:
            print(f"I am that node!")
            continue

        await registerMyself(f"ws://{nodeIP}:{nodePort}", doRespond=True)

    print(nodes)
    if len(list(nodes.keys())) != 0:
        await fetchLedger(random.choice(list(nodes.keys())))

    await verifyLedger()

    print(f"Booting on {ip}:{myPort}")
    await websockets.serve(ledgerServer, "0.0.0.0", myPort+1)
    await updateVotingWeights()
    await asyncio.Event().wait()

asyncio.run(run())

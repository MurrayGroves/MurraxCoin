import asyncio

import websockets
import random
import json
from aioconsole import ainput
import os
import traceback

from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Hash import BLAKE2b
from Crypto.Signature import DSS

from nacl.signing import SigningKey

import base64
import zlib

privateFile = input("Private Key Path: ")

websocketPool = {}

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP


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


async def genSignature(data, privateKey):
    data = json.dumps(data).encode()
    signature = privateKey.sign(data).signature
    signature = hex(int.from_bytes(signature, "little"))

    return signature

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
print(f"Your address: {publicKeyStr}")

doBackgroundCheck = True
websocket = None


async def receive(sendAmount, block):
    global websocket

    resp = await wsRequest(f'{{"type": "balance", "address": "{publicKeyStr}"}}')
    resp = json.loads(resp)

    if resp["type"] != "rejection":
        balance = float(resp["balance"])
        blockType = "receive"
        response = await wsRequest(f'{{"type": "getPrevious", "address": "{publicKeyStr}"}}')
        previous = json.loads(response)["link"]

    else:
        balance = 0
        blockType = "open"
        previous = "0" * 20

    response = await wsRequest(json.dumps({"type": "getRepresentative", "address": publicKeyStr}))
    representative = json.loads(response)["representative"]

    block = {"type": f"{blockType}", "previous": f"{previous}", "address": f"{publicKeyStr}",
             "link": f"{block}", "balance": balance + float(sendAmount), "representative": representative}

    hasher = BLAKE2b.new(digest_bits=512)
    blockID = hasher.update(json.dumps(block).encode("utf-8")).hexdigest()
    block["id"] = blockID
    signature = await genSignature(block, privateKey)
    block = {**block, **{"signature": signature}}
    resp = await wsRequest(json.dumps(block))
    resp = json.loads(resp)

    if resp["type"] == "confirm":
        receiveAmount = sendAmount
        newBalance = block["balance"]
        print(f"\nReceived MXC: {receiveAmount}")
        print(f"New Balance: {newBalance}")
        print("Send or Delegate? (s/d)")

    else:
        print("\nFailed to receive MXC!")
        print(resp)


async def sendAlert(data):
    data = json.loads(data)
    await receive(data["sendAmount"], data["link"])


async def websocketPoolLoop():
    global websocketPool
    while True:
        await asyncio.sleep(0.03)
        try:
            resp = await asyncio.wait_for(websocket.recv(), 0.5)
            if prevRequest == "":
                if json.loads(resp)["type"] == "sendAlert":
                    asyncio.create_task(sendAlert(resp))

                else:
                    print("Unknown Alert")
                    print(resp)

                continue

            else:
                websocketPool[prevRequest][1] = resp
                prevRequest = ""

        except ValueError:
            traceback.print_exc()

        except:
            pass

        if len(websocketPool.keys()) > 0:
            poolKeys = list(websocketPool.keys())
            if websocketPool[poolKeys[0]][1] == "":
                await websocket.send(websocketPool[poolKeys[0]][0])
                prevRequest = poolKeys[0]
                websocketPool[poolKeys[0]][1] = 0


async def wsRequest(request):
    global websocketPool
    requestID = random.randint(0, 99999999999999)
    websocketPool[requestID] = [request, ""]
    while True:
        await asyncio.sleep(0.1)
        if websocketPool[requestID][1] != "" and websocketPool[requestID][1] != 0:
            resp = websocketPool[requestID][1]
            websocketPool.pop(requestID)
            return resp


async def ping():
    resp = await wsRequest('{"type": "ping"}')
    return resp


async def main():
    global websocket
    uri = "ws://murraxcoin.murraygrov.es:6969"
    websocket = await websocketSecure.connect(uri)

    asyncio.create_task(websocketPoolLoop())

    await ping()

    resp = await wsRequest(f'{{"type": "balance", "address": "{publicKeyStr}"}}')
    resp = json.loads(resp)

    if resp["type"] != "rejection":
        balance = float(resp["balance"])

    else:
        balance = 0

    print(f"Balance: {balance}")
    req = {"type": "pendingSend", "address": publicKeyStr}
    resp = await wsRequest(json.dumps(req))
    resp = json.loads(resp)

    if resp["link"] != "":
        await receive(resp["sendAmount"], resp["link"])

    req = {"type": "watchForSends", "address": publicKeyStr}
    await wsRequest(json.dumps(req))

    while True:
        blockID = str(random.randint(0, 99999999999999999999))
        blockID = "0" * (20 - len(blockID)) + blockID
        action = await ainput("Send or Delegate? (s/d) ")
        if action == "s":
            sendAddress = await ainput("Send Address: ")
            toSend = await ainput("Amount to send: ")
            toSend = int(toSend)

            resp = await wsRequest(f'{{"type": "balance", "address": "{publicKeyStr}"}}')
            resp = json.loads(resp)

            if resp["type"] != "rejection":
                balance = float(resp["balance"])

            else:
                balance = 0

            newBalance = balance - toSend

            response = await wsRequest(f'{{"type": "getPrevious", "address": "{publicKeyStr}"}}')
            previous = json.loads(response)["link"]

            response = await wsRequest(json.dumps({"type": "getRepresentative", "address": publicKeyStr}))
            representative = json.loads(response)["representative"]

            data = {"type": "send", "address": f"{publicKeyStr}", "link": f"{sendAddress}", "balance": f"{newBalance}", "id": f"{blockID}", "previous": previous, "representative": representative}

            signature = await genSignature(data, privateKey)
            data = {**data, **{"signature": f"{signature}"}}
            resp = await wsRequest(json.dumps(data))
            if json.loads(resp)["type"] == "confirm":
                print("MXC send initiated!")

            else:
                print("MXC send failed to initiate, please see error below:")
                print(resp)

        elif action == "d":
            delegateAddress = await ainput("Delegate Address: ")
            response = await wsRequest(f'{{"type": "getPrevious", "address": "{publicKeyStr}"}}')
            previous = json.loads(response)["link"]

            data = {"type": "change", "address": publicKeyStr, "balance": balance, "representative": delegateAddress, "previous": previous}
            hasher = BLAKE2b.new(digest_bits=512)
            blockID = hasher.update(json.dumps(data).encode("utf-8")).hexdigest()
            data["id"] = blockID
            signature = await genSignature(data, privateKey)
            data["signature"] = signature

            resp = await wsRequest(json.dumps(data))
            if json.loads(resp)["type"] == "confirm":
                print("Delegation change initiated!")

            else:
                print("MXC delegation change failed to initiate, please see error below:")
                print(resp)

asyncio.get_event_loop().run_until_complete(main())

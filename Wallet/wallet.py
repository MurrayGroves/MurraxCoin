import asyncio
import websockets
import random
import json
import time
from aioconsole import ainput

from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Signature import DSS

publicFile = input("Public Key Path: ")
privateFile = input("Private Key Path: ")

async def ping(websocket):
    await websocket.send('{"type": "ping"}')
        
    resp = await websocket.recv()
    print(resp)

async def genSignature(data, privateKey):
    data = json.dumps(data)
    signer = DSS.new(privateKey, "deterministic-rfc6979")
    signatureHash = SHA256.new()
    signatureHash.update(data.encode("utf-8"))
    signature = signer.sign(signatureHash)
    signature = hex(int.from_bytes(signature, "little"))

    return signature


try:
    f = open(privateFile, "rt")
    privateKey = ECC.import_key(f.read())
    f.close()

except:
    privateKey = ECC.generate(curve="P-256")
    f = open(privateFile, "wt")
    f.write(privateKey.export_key(format="PEM"))
    f.close()

try:
    f = open(publicFile, "rt")
    publicKey = ECC.import_key(f.read())
    f.close()

except:
    publicKey = privateKey.public_key()
    f = open(publicFile, "wt")
    f.write(publicKey.export_key(format="PEM"))
    f.close()

publicKeyStr = publicKey.export_key(format="PEM", compress=True)
print("\n")
print(publicKeyStr)

publicKeyStr = publicKeyStr.replace("-----BEGIN PUBLIC KEY-----\n", "")
publicKeyStr = publicKeyStr.replace("\n-----END PUBLIC KEY-----", "")
publicKeyStr = publicKeyStr.replace("\n", " ")
print(publicKeyStr)

doBackgroundCheck = True
websocket = None


async def receive(sendAmount, block):
    global websocket

    await websocket.send(f'{{"type": "balance", "address": "{publicKeyStr}"}}')
    resp = await websocket.recv()
    resp = json.loads(resp)

    if resp["type"] != "rejection":
        balance = int(resp["balance"])

    else:
        balance = 0

    if balance == 0:
        blockType = "open"
        previous = "0" * 20

    else:
        blockType = "receive"
        await websocket.send(f'{{"type": "getPrevious", "address": "{publicKeyStr}"}}')
        response = await websocket.recv()
        previous = json.loads(response)["link"]

    blockID = str(random.randint(0, 99999999999999999999))
    blockID = "0" * (20 - len(blockID)) + blockID
    block = {"type": f"{blockType}", "id": blockID, "previous": f"{previous}", "address": f"{publicKeyStr}",
             "link": f"{block}", "balance": balance + sendAmount}

    signature = await genSignature(block, privateKey)
    block = {**block, **{"signature": signature}}
    await websocket.send(json.dumps(block))
    resp = await websocket.recv()
    resp = json.loads(resp)

    if resp["type"] == "confirm":
        receiveAmount = sendAmount
        newBalance = block["balance"]
        print(f"Received MXC: {receiveAmount}")
        print(f"New Balance: {newBalance}")

    else:
        print("Failed to receive MXC!")
        print(resp)


async def sendAlert(data):
    await receive(data["sendAmount"], data["link"])


async def loop():
    while True:
        # Ok, so websockets don't link data at all. If this thread sends something while the main thread is doing something else, the main thread will get this response instead.
        if not doBackgroundCheck:
            await asyncio.sleep(5)
            continue

        data = await websocket.recv()
        data = json.loads(data)
        if data["type"] == "sendAlert":
            await sendAlert(data)

        else:
            print("Unknown alert")
            print(data)


async def main():
    global websocket
    uri = "ws://qwhwdauhdasht.ddns.net:6969"
    websocket = await websockets.connect(uri)

    global doBackgroundCheck
    doBackgroundCheck = False
    asyncio.create_task(loop())

    await ping(websocket)

    await websocket.send(f'{{"type": "balance", "address": "{publicKeyStr}"}}')
    resp = await websocket.recv()
    resp = json.loads(resp)


    if resp["type"] != "rejection":
        balance = int(resp["balance"])

    else:
        balance = 0

    print(f"Balance: {balance}")
    req = {"type": "pendingSend", "address": publicKeyStr}
    await websocket.send(json.dumps(req))
    resp = await websocket.recv()
    resp = json.loads(resp)

    if resp["link"] != "":
        await receive(resp["sendAmount"], resp["link"])

    req = {"type": "watchForSends", "address": publicKeyStr}
    await websocket.send(json.dumps(req))
    resp = await websocket.recv()

    doBackgroundCheck = True
    while True:
        sendAddress = await ainput("Send Address: ")
        toSend = await ainput("Amount to send: ")
        toSend = int(toSend)

        doBackgroundCheck = False

        newBalance = balance - toSend
        blockID = str(random.randint(0, 99999999999999999999))
        blockID = "0"*(20-len(blockID)) + blockID

        await websocket.send(f'{{"type": "getPrevious", "address": "{publicKeyStr}"}}')
        response = await websocket.recv()
        previous = json.loads(response)["link"]

        data = {"type": "send", "address": f"{publicKeyStr}", "link": f"{sendAddress}", "balance": f"{newBalance}", "id": f"{blockID}", "previous": previous}

        signature = await genSignature(data, privateKey)
        data = {**data, **{"signature": f"{signature}"}}
        await websocket.send(json.dumps(data))
        resp = await websocket.recv()
        print(resp)
        doBackgroundCheck = True


asyncio.get_event_loop().run_until_complete(main())
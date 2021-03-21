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

async def loop(websocket):
    while True:
        # Ok, so websockets don't link data at all. If this thread sends something while the main thread is doing something else, the main thread will get this response instead.
        if not doBackgroundCheck:
            await asyncio.sleep(5)
            continue

        await websocket.send(f'{{"type": "pendingSend", "address": "{publicKeyStr}"}}')
        response = await websocket.recv()
        pendingSend = json.loads(response)

        if pendingSend["link"] == "":
            await asyncio.sleep(5)
            continue

        await websocket.send(f'{{"type": "balance", "address": "{publicKeyStr}"}}')
        resp = await websocket.recv()
        resp = json.loads(resp)

        if resp["type"] != "rejection":
            balance = int(resp["balance"])

        else:
            balance = 0

        if balance == 0:
            blockType = "open"
            previous = "0"*20

        else:
            blockType = "receive"
            await websocket.send(f'{{"type": "getPrevious", "address": "{publicKeyStr}"}}')
            response = await websocket.recv()
            previous = json.loads(response)["link"]

        link = pendingSend["link"]
        blockID = str(random.randint(0, 99999999999999999999))
        blockID = "0" * (20 - len(blockID)) + blockID
        block = {"type": f"{blockType}", "id": blockID, "previous": f"{previous}", "address": f"{publicKeyStr}", "link": f"{link}", "balance": balance+pendingSend["sendAmount"]}
        signature = await genSignature(block, privateKey)
        block = {**block, **{"signature": signature}}

        await websocket.send(json.dumps(block))
        resp = await websocket.recv()
        print(resp)

        await asyncio.sleep(5)

async def main():
    uri = "ws://qwhwdauhdasht.ddns.net:6969"
    websocket = await websockets.connect(uri)
    asyncio.create_task(loop(websocket))

    global doBackgroundCheck
    doBackgroundCheck = False

    await ping(websocket)

    await websocket.send(f'{{"type": "balance", "address": "{publicKeyStr}"}}')
    resp = await websocket.recv()
    resp = json.loads(resp)

    doBackgroundCheck = True

    if resp["type"] != "rejection":
        balance = int(resp["balance"])

    else:
        balance = 0

    print(f"Balance: {balance}")

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
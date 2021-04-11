import asyncio
import websockets
import random
import json
from aioconsole import ainput

from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Signature import DSS

publicFile = input("Public Key Path: ")
privateFile = input("Private Key Path: ")

websocketPool = {}


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

    resp = await wsRequest(f'{{"type": "balance", "address": "{publicKeyStr}"}}')
    resp = json.loads(resp)

    if resp["type"] != "rejection":
        balance = int(resp["balance"])
        blockType = "receive"
        response = await wsRequest(f'{{"type": "getPrevious", "address": "{publicKeyStr}"}}')
        previous = json.loads(response)["link"]

    else:
        balance = 0
        blockType = "open"
        previous = "0" * 20


    blockID = str(random.randint(0, 99999999999999999999))
    blockID = "0" * (20 - len(blockID)) + blockID
    block = {"type": f"{blockType}", "id": blockID, "previous": f"{previous}", "address": f"{publicKeyStr}",
             "link": f"{block}", "balance": balance + sendAmount}

    signature = await genSignature(block, privateKey)
    block = {**block, **{"signature": signature}}
    resp = await wsRequest(json.dumps(block))
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


async def websocketPoolLoop():
    global websocketPool
    while True:
        await asyncio.sleep(0.3)
        try:
            resp = await asyncio.wait_for(websocket.recv(), 0.5)
            if prevRequest == "":
                if json.loads(resp)["type"] == "sendAlert":
                    await sendAlert(resp)

                else:
                    print("Unknown Alert")
                    print(resp)

                continue

            else:
                websocketPool[prevRequest][1] = resp

        except:
            pass

        prevRequest = ""
        if len(websocketPool.keys()) > 0:
            poolKeys = list(websocketPool.keys())
            if websocketPool[poolKeys[0]][1] == "":
                await websocket.send(websocketPool[poolKeys[0]][0])
                prevRequest = poolKeys[0]


async def wsRequest(request):
    global websocketPool
    requestID = random.randint(0, 99999999999999)
    websocketPool[requestID] = [request, ""]
    while True:
        await asyncio.sleep(0.1)
        if websocketPool[requestID][1] != "":
            resp = websocketPool[requestID][1]
            websocketPool.pop(requestID)
            return resp


async def ping():
    resp = await wsRequest('{"type": "ping"}')
    return resp


async def main():
    global websocket
    uri = "ws://qwhwdauhdasht.ddns.net:6969"
    websocket = await websockets.connect(uri)

    asyncio.create_task(websocketPoolLoop())

    await ping()

    resp = await wsRequest(f'{{"type": "balance", "address": "{publicKeyStr}"}}')
    resp = json.loads(resp)

    if resp["type"] != "rejection":
        balance = int(resp["balance"])

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
        sendAddress = await ainput("Send Address: ")
        toSend = await ainput("Amount to send: ")
        toSend = int(toSend)

        newBalance = balance - toSend
        blockID = str(random.randint(0, 99999999999999999999))
        blockID = "0"*(20-len(blockID)) + blockID

        response = await wsRequest(f'{{"type": "getPrevious", "address": "{publicKeyStr}"}}')
        previous = json.loads(response)["link"]

        data = {"type": "send", "address": f"{publicKeyStr}", "link": f"{sendAddress}", "balance": f"{newBalance}", "id": f"{blockID}", "previous": previous}

        signature = await genSignature(data, privateKey)
        data = {**data, **{"signature": f"{signature}"}}
        resp = await wsRequest(json.dumps(data))
        if json.loads(resp)["type"] == "confirm":
            print("MXC Sent!")

        else:
            print("MXC failed to send")
            print(resp)

asyncio.get_event_loop().run_until_complete(main())
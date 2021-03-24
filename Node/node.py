import asyncio
import json
import aiofiles

import websockets
import aiohttp

import os
import random

from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC

entrypoints = ["ws://qwhwdauhdasht.ddns.net:6969"]
ledgerDir = input("Ledger Directory:")
if ledgerDir == "":
    ledgerDir = "Accounts/"

os.makedirs(ledgerDir, exist_ok=True)

nodes = {}

ip = -1
myPort = -1


async def balance(data):
    address = data["address"]

    try:
        block = await getHead(address)

    except FileNotFoundError:
        response = f'{{"type": "rejection", "address": "{address}", "reason": "addressNonExistent"}}'
        return response

    response = f'{{"type": "info", "address": "{address}", "balance": "{block["balance"]}" }}'
    return response


async def checkForPendingSend(data):
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
                    amount = int(amount["balance"]) - int(block["balance"])

                    resp = {"type": "pendingSend", "link": f"{block['address']}/{block['id']}", "sendAmount": amount}
                    resp = json.dumps(resp)
                    return resp

    response = {"type": "pendingSend", "link": "", "sendAmount": ""}
    return json.dumps(response)


async def fetchNodes():
    global nodes
    nodeAddresses = ""
    for node in nodes:
        nodeAddresses = nodeAddresses + "|" + node

    response = {"type": "confirm", "action": "fetchNodes", "nodes": nodeAddresses}
    return json.dumps(response)


async def getBlock(address, blockID):
    f = await aiofiles.open(f"{ledgerDir}{address}")
    fileStr = await f.read()
    await f.close()
    fileStr = fileStr.splitlines()

    blocks = []
    for block in fileStr:
        blocks.append(json.loads(block))

    for block in blocks:
        if block["id"] == blockID:
            return block


async def getHead(address):
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


async def openAccount(data):
    signature = data["signature"]
    address = data["address"]
    blockID = data["id"]

    valid = await verifySignature(signature, address, data)
    if not valid:
        toRespond = f'{{"type": "rejection", "address": "{address}", "id": "{blockID}", "reason": "signature"}}'
        return toRespond

    sendingAddress, sendingBlock = data["link"].split("/")
    sendingBlock = await getBlock(sendingAddress, sendingBlock)

    # Check that send block is valid
    valid = await verifySignature(sendingBlock["signature"], sendingAddress, sendingBlock)
    if not valid:
        toRespond = f'{{"type": "rejection", "address": "{address}", "id": "{blockID}", "reason": "sendSignature"}}'
        return toRespond

    previousBlock = await getBlock(sendingAddress, sendingBlock["previous"])
    sendAmount = int(previousBlock["balance"]) - int(sendingBlock["balance"])

    if int(data["balance"]) != int(sendAmount):
        toRespond = f'{{"type": "rejection", "address": "{address}", "id": "{blockID}", "reason": "invalidBalance"}}'
        return toRespond

    if data["previous"] != "0"*20:
        toRespond = f'{{"type": "rejection", "address": "{address}", "id": "{blockID}", "reason": "invalidPrevious"}}'
        return toRespond

    toRespond = f'{{"type": "confirm", "address": "{address}", "id": "{blockID}"}}'
    return toRespond


async def receive(data):
    signature = data["signature"]
    address = data["address"]
    blockID = data["id"]

    valid = await verifySignature(signature, address, data)
    if not valid:
        toRespond = f'{{"type": "rejection", "address": "{address}", "id": "{blockID}", "reason": "signature"}}'
        return toRespond

    sendingAddress, sendingBlock = data["link"].split("/")
    sendingBlock = await getBlock(sendingAddress, sendingBlock)

    # Check that send block is valid
    valid = await verifySignature(sendingBlock["signature"], sendingAddress, sendingBlock)
    if not valid:
        toRespond = f'{{"type": "rejection", "address": "{address}", "id": "{blockID}", "reason": "sendSignature"}}'
        return toRespond
    
    f = await aiofiles.open(f"{ledgerDir}{address}")
    blocks = await f.read()
    await f.close()
    blocks = blocks.splitlines()
    for block in blocks:
        if json.loads(block)["link"] == data["link"]:
            response = {"type": "rejection", "address": address, "id": blockID, "reason": "doubleReceive"}
            return json.dumps(response)

    previousBlock = await getBlock(sendingAddress, sendingBlock["previous"])
    sendAmount = previousBlock["balance"] - int(sendingBlock["balance"])

    head = await getHead(address)
    if int(data["balance"]) != int(head["balance"]) + int(sendAmount):
        toRespond = f'{{"type": "rejection", "address": "{address}", "id": "{blockID}", "reason": "invalidBalance"}}'
        return toRespond

    if data["previous"] != head["id"]:
        toRespond = f'{{"type": "rejection", "address": "{address}", "id": "{blockID}", "reason": "invalidPrevious"}}'
        return toRespond

    toRespond = f'{{"type": "confirm", "address": "{address}", "id": "{blockID}"}}'
    return toRespond


async def registerMyself(node):
    global myPort
    global ip
    print(f"Registering with {node}")
    websocket = await websockets.connect(node)
    await websocket.send(f'{{"type": "registerNode", "port": "{myPort}"}}')
    resp = await websocket.recv()
    if json.loads(resp)["type"] == "confirm":
        print(f"Node registered with: {node}")
        global nodes
        nodes = {**nodes, **{node: websocket}}

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
            isLocalMachine = (nodeIP == "localhost" or nodeIP == "127.0.0.1") and str(myPort) == str(node.split(":")[2])
            if node not in nodes and not isLocalMachine:
                await registerMyself(node)

    else:
        await websocket.close()
        print(f"Failed to register with: {node}")


async def send(data):
    signature = data["signature"]
    address = data["address"]
    blockID = data["id"]

    valid = await verifySignature(signature, address, data)
    if not valid:
        toRespond = f'{{"type": "rejection", "address": "{address}", "id": "{blockID}", "reason": "signature"}}'
        return toRespond

    head = await getHead(address)
    if int(head["balance"]) < int(data["balance"]):
        toRespond = f'{{"type": "rejection", "address": "{address}", "id": "{blockID}", "reason": "balance"}}'
        return toRespond

    toRespond = f'{{"type": "confirm", "address": "{address}", "id": "{blockID}"}}'
    return toRespond


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


async def incoming(websocket, path):
    print(f"Client Connected: {websocket.remote_address[0]}")
    while True:
        try:
            data = await websocket.recv()

        except:
            print("Client Disconnected")
            break

        print(data)
        data = json.loads(data)
        if data["type"] == "ping":
            response = '{"type": "confirm", "action": "ping"}'

        elif data["type"] == "balance":
            response = await balance(data)

        elif data["type"] == "send":
            response = await send(data)
            if json.loads(response)["type"] == "confirm":
                f = await aiofiles.open(f"{ledgerDir}{data['address']}", "a")
                await f.write(json.dumps(data))
                await f.close()

        elif data["type"] == "pendingSend":
            response = await checkForPendingSend(data)

        elif data["type"] == "receive":
            response = await receive(data)
            if json.loads(response)["type"] == "confirm":
                f = await aiofiles.open(f"{ledgerDir}{data['address']}", "a")
                await f.write(json.dumps(data))
                await f.close()

        elif data["type"] == "open":
            response = await openAccount(data)
            if json.loads(response)["type"] == "confirm":
                f = await aiofiles.open(f"{ledgerDir}{data['address']}", "a+")
                await f.write(json.dumps(data))
                await f.close()

        elif data["type"] == "getPrevious":
            head = await getHead(data["address"])
            address = data["address"]
            previous = head["id"]
            response = f'{{"type": "previous", "address": "{address}", "link": "{previous}"}}'

        elif data["type"] == "registerNode":
            response = json.dumps({"type": "confirm", "action": "registerNode"})
            global nodes
            nodes = {**nodes, **{f"ws://{websocket.remote_address[0]}:{data['port']}": websocket}}

        elif data["type"] == "fetchNodes":
            response = await fetchNodes()

        else:
            response = f'{{"type": "rejection", "reason": "unknown request"}}'

        await websocket.send(response)


async def ledgerServer(websocket, url):
    for account in os.listdir(ledgerDir):
        await websocket.send(f"Account:{account}")
        f = await aiofiles.open(ledgerDir + account)
        toSend = await f.read()
        await f.close()
        for line in toSend.splitlines():
            await websocket.send(line)

    await websocket.send("ayothatsall")


async def fetchLedger(node):
    node = node.split(":")[0] + ":" + node.split(":")[1] + ":" + str(int(node.split(":")[2])+1)
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
        websocket = await asyncio.wait_for(websockets.connect(url), 3)
        await websocket.send('{"type": "ping"}')
        await websocket.recv()
        await websocket.close()

        return True

    except:
        return False


async def run():
    global ip
    global myPort
    # Get my public IP
    async with aiohttp.ClientSession() as session:
        async with session.get('https://api.ipify.org') as response:
            ip = await response.text()

    if await testWebsocket(f"ws://{ip}:6969"):
        # A node already exists on our network, so boot on the secondary port
        await websockets.serve(incoming, "0.0.0.0", 5858)
        myPort = 5858
        entrypoints.append(f"ws://{ip}:6969")

    elif await testWebsocket(f"ws://localhost:6969"):
        # A node already exists on our computer, so boot on the secondary port
        await websockets.serve(incoming, "0.0.0.0", 5858)
        myPort = 5858
        entrypoints.append(f"ws://localhost:6969")

    else:
        # No other nodes exist on our network, so boot on the primary port
        await websockets.serve(incoming, "0.0.0.0", 6969)
        myPort = 6969

    for node in entrypoints:
        if not await testWebsocket(node):
            print(f"Node not available: {node}")
            continue

        nodeIP = node.replace("ws://", "").split(":")[0]
        isLocalMachine = (nodeIP == "localhost" or nodeIP == "127.0.0.1") and str(myPort) == str(node.split(":")[2])
        if isLocalMachine:
            print(f"I am that node!")
            continue

        await registerMyself(node)

    if len(list(nodes.keys())) != 0:
        await fetchLedger(random.choice(list(nodes.keys())))

    print(f"Booting on {ip}:{myPort}")
    await websockets.serve(ledgerServer, "0.0.0.0", myPort+1)
    await asyncio.Event().wait()

asyncio.run(run())

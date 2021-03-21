import asyncio
import json
import aiofiles

import requests
import websockets

import os

from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC

entrypoints = ["ws://qwhwdauhdasht.ddns.net:6969"]
nodes = {}

async def create(data):
    address = data["address"]

async def balance(data):
    address = data["address"]

    try:
        block = await getHead(address)

    except FileNotFoundError:
        response = f'{{"type": "rejection", "address": "{address}", "reason": "addressNonExistent"}}'
        return response

    balance = block["balance"]

    response = f'{{"type": "info", "address": "{address}", "balance": "{balance}" }}'
    return response

async def checkForPendingSend(data):
    address = data["address"]

    dir = os.listdir("Accounts")

    received = []
    if address in dir:
        f = await aiofiles.open("Accounts/" + address)
        data = await f.read()
        await f.close()

        data = data.splitlines()
        for block in data:
            block = json.loads(block)
            if block["type"] == "receive":
                received.append(block["link"])

            if block["type"] == "open":
                received.append(block["link"])

    for i in dir:
        f = await aiofiles.open(f"Accounts/{i}")
        blocks = await f.read()
        await f.close()
        blocks = blocks.splitlines()
        for block in blocks:
            block = json.loads(block)
            if f'{block["address"]}/{block["id"]}' in received:
                continue

            if block["type"] == "send":
                if block["link"] == address:
                    sendAmount = await getBlock(block["address"], block["previous"])
                    sendAmount = int(sendAmount["balance"]) - int(block["balance"])
                    response = json.dumps({"type": "pendingSend", "link": f"{block['address']}/{block['id']}", "sendAmount": sendAmount})
                    return response

    response = {"type": "pendingSend", "link": "", "sendAmount": ""}
    return json.dumps(response)


async def getBlock(address, blockID):
    f = await aiofiles.open(f"Accounts/{address}")
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
    f = await aiofiles.open(f"Accounts/{address}")
    fileStr = await f.read()
    await f.close()
    fileStr = fileStr.splitlines()

    blocks = []
    for block in fileStr:
        blocks.append(json.loads(block))

    if len(blocks) == 1:
        return blocks[0]

    # Sort blocks in order
    sorted = False
    while not sorted:
        sorted = True
        for i in range(1, len(blocks)):
            previous = blocks[i]["previous"]
            if previous == "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000":
                blocks.insert(0, blocks.pop(i))
                continue

            if blocks[i-1]["id"] == previous:
                continue

            sorted = False

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

    # Check that send block is valid (just in case)
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

    f = await aiofiles.open(f"Accounts/{address}", "a+")
    await f.write(json.dumps(data))
    await f.close()

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

    # Check that send block is valid (just in case)
    valid = await verifySignature(sendingBlock["signature"], sendingAddress, sendingBlock)
    if not valid:
        toRespond = f'{{"type": "rejection", "address": "{address}", "id": "{blockID}", "reason": "sendSignature"}}'
        return toRespond
    
    f = await aiofiles.open(f"Accounts/{address}")
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

    f = await aiofiles.open(f"Accounts/{address}", "a")
    await f.write("\n" + json.dumps(data))
    await f.close()

    toRespond = f'{{"type": "confirm", "address": "{address}", "id": "{blockID}"}}'
    return toRespond


async def send(data):
    signature = data["signature"]
    address = data["address"]
    blockID = data["id"]

    valid = await verifySignature(signature, address, data)
    if not valid:
        toRespond = f'{{"type": "rejection", "address": "{address}", "id": "{blockID}", "reason": "signature"}}'
        return toRespond

    destination = data["link"]
    balance = data["balance"]

    print(balance)

    head = await getHead(address)
    print(int(head["balance"]))
    if int(head["balance"]) < int(balance):
        toRespond = f'{{"type": "rejection", "address": "{address}", "id": "{blockID}", "reason": "balance"}}'
        return toRespond

    previous = head["id"]
    f = await aiofiles.open(f"Accounts/{address}", "a")
    await f.write("\n" + json.dumps(data))
    await f.close()

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

    except Exception as e:
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

        elif data["type"] == "create":
            response = await create(data)

        elif data["type"] == "balance":
            response = await balance(data)

        elif data["type"] == "send":
            response = await send(data)

        elif data["type"] == "pendingSend":
            response = await checkForPendingSend(data)

        elif data["type"] == "receive":
            response = await receive(data)

        elif data["type"] == "open":
            response = await openAccount(data)

        elif data["type"] == "getPrevious":
            head = await getHead(data["address"])
            address = data["address"]
            previous = head["id"]
            response = f'{{"type": "previous", "address": "{address}", "link": "{previous}"}}'

        elif data["type"] == "registerNode":
            global nodes
            nodes = {**nodes, **{f"ws://{websocket.remote_address[0]}:{data['port']}": websocket}}

            response = json.dumps({"type": "confirm", "action": "registerNode"})

        else:
            response = f'{{"type": "rejection", "reason": "unknown request"}}'

        if not response:
            print(data)

        await websocket.send(response)


# Check if node running on given url
async def testWebsocket(url):
    try:
        async with websockets.connect(url) as websocket:
                await websocket.send('{"type": "ping"}')
                resp = await websocket.recv()

        return True

    except:
        return False


ip = requests.get('https://api.ipify.org').text  # Get my public IP
if asyncio.get_event_loop().run_until_complete(testWebsocket(f"ws://{ip}:6969")):
    start_server = websockets.serve(incoming, "0.0.0.0", 5858)  # A node already exists on our network, so boot on the secondary port
    myPort = 5858

else:
    start_server = websockets.serve(incoming, "0.0.0.0", 6969)  # No other nodes exist on our network, so boot on the primary port
    myPort = 6969

async def registerMyself(node):
    websocket = await websockets.connect(node)
    await websocket.send(f'{{"type": "registerNode", "port": "{myPort}"}}')
    resp = await websocket.recv()
    if json.loads(resp)["type"] == "confirm":
        print(f"Node registered with: {node}")
        global nodes
        nodes = {**nodes, **{node: websocket}}

    else:
        print(f"Failed to register with: {node}")

for node in entrypoints:
    if not asyncio.get_event_loop().run_until_complete(testWebsocket(node)):
        print(f"Node not available: {node}")
        continue

    asyncio.get_event_loop().run_until_complete(registerMyself(node))

print(f"Booting on {ip}:{myPort}")
asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()
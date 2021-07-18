import json
import aiofiles
import os

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

from node import getHead

ledgerDir = "data/Accounts/"


# Send account heads
async def request_heads(ws, session_key):
    transmissionChunks = [""]
    chunkHeads = 0
    curChunk = 0
    for account in os.listdir(ledgerDir):
        if chunkHeads >= 320:  # Split transmission in chunks of 320 accounts
            chunkHeads = 0
            curChunk += 1
            transmissionChunks.append("")

        head = await getHead(account)
        head = head["id"]
        transmissionChunks[curChunk] += f"{account}+{head}/"

    for chunk in transmissionChunks:
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(chunk.encode("utf-8"))
        await ws.send(ciphertext.hex() + "|||" + tag.hex() + "|||" + cipher_aes.nonce.hex())


# Send an entire account
async def request_account(ws, session_key, account, head):
    f = await aiofiles.open(ledgerDir+account)
    blocks = await f.read()
    await f.close()

    start = True if head=="" else False
    blocks = blocks.splitlines()
    for block in blocks:
        if not start and json.loads(block)["id"] == head:
            start = True
            continue

        if not start:
            continue
        print(block)
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(block.encode("utf-8"))
        await ws.send(ciphertext.hex() + "|||" + tag.hex() + "|||" + cipher_aes.nonce.hex())


# Handle bootstrap connections
async def bootstrap_server(ws, url):
    recipientKey = await ws.recv()
    recipientKey = RSA.import_key(recipientKey)
    session_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(recipientKey)
    enc_session_key = cipher_rsa.encrypt(session_key)
    sessionKey = enc_session_key.hex()
    await ws.send(json.dumps({"type": "sessionKey", "sessionKey": sessionKey}))

    print(f"Client Connected on bootstrap network: {ws.remote_address[0]}")

    while True:
        try:
            data = await ws.recv()
            ciphertext, tag, nonce = data.split("|||")
            ciphertext, tag, nonce = bytes.fromhex(ciphertext), bytes.fromhex(tag), bytes.fromhex(nonce)
            cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
            plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)
            data = plaintext.decode("utf-8")

        except:
            print("Client Disconnected on bootstrap network")
            break

        data = json.loads(data)
        if data["type"] == "getHeads":
            await request_heads(ws, session_key)
            response = {"type": "endHeadsTransmission"}

        elif data["type"] == "requestAccount":
            await request_account(ws, session_key, data["address"], data["head"])
            response = {"type": "endAccountTransmission"}

        else:
            response = {"type": "rejection", "reason": "unknown request"}

        response = json.dumps(response)
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(response.encode("utf-8"))
        await ws.send(ciphertext.hex() + "|||" + tag.hex() + "|||" + cipher_aes.nonce.hex())

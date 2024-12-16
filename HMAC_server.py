#!/usr/bin/env python
# Серверная часть

import asyncio
import websockets
import hashlib

def gen_sha256_hmac(message, key):
    '''
    Source: https://ru.wikipedia.org/wiki/HMAC
    '''

    blocksize = 64

    # aka ipad
    trans_5C = bytes((x ^ 0x5C) for x in range(256))

    # aka opad
    trans_36 = bytes((x ^ 0x36) for x in range(256))

    key_hex = key.encode().hex()[2:]

    # Convert hex key to bytes object
    key_bytes = bytes.fromhex(key_hex)

    # Add a zero-bytes padding to apply to blocksize
    key_bytes = key_bytes.ljust(blocksize, b'\0')

    # Xor each byte with 0x36 constant
    # K0 ⊕ ipad :
    xored_key_bytes_ipad = key_bytes.translate(trans_36)

    # Concatinate last value with hex-encoded message and do SHA256 on it
    h1 = hashlib.sha256(xored_key_bytes_ipad + message.encode())

    # Xor each byte with 0x5C constant
    xored_key_bytes_opad = key_bytes.translate(trans_5C)

    # Now concat last value and previous hash-obj and do SHA256 on it
    return hashlib.sha256(xored_key_bytes_opad + h1.digest()).hexdigest()

async def handler(websocket, path):
    async for message in websocket:
        msg, hmac = message.split(',')
        shared_key = "supersecret"
        # Генерация HMAC для проверки
        expected_hmac = gen_sha256_hmac(msg, shared_key)
        
        if hmac == expected_hmac:
            response = "Valid message"
        else:
            response = "Invalid message"

        await websocket.send(response)

start_server = websockets.serve(handler, "localhost", 1234)

asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()

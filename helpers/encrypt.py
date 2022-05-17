from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import hashlib


def aes(payload, key):
    iv = 16 * b'\x00'
    cipher = AES.new(hashlib.sha256(key).digest(), AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(payload, AES.block_size))

    encryptedPayload = '0x' + ', 0x'.join(hex(x)[2:] for x in ciphertext)
    return encryptedPayload


def xor(payload, key):
    
    KEY = key
    output_str = ""

    if isinstance(payload[0], str):
        for i in range(len(payload)):
            current = payload[i]
            current_key = KEY[i % len(KEY)]
            output_str += chr(ord(current) ^ current_key)
    else:
        for i in range(len(payload)):
            current = payload[i]
            current_key = KEY[i % len(KEY)]
            output_str += chr(current ^ current_key)
    
    
    encryptedPayload = '0x' + ', 0x'.join(hex(ord(x))[2:] for x in output_str)
    return encryptedPayload

def format(payload):
    output_str = ""
    for i in range(len(payload)):
        output_str += chr(payload[i])
    formattedPayload = '0x' + ', 0x'.join(hex(ord(x))[2:] for x in output_str)
    return formattedPayload
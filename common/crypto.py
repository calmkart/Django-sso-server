# -*- coding:utf-8 -*-
import base64
from Crypto import Random
from Crypto.Hash import SHA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex

#AES加解密,用于本地加密数据库密码和rsa private key
aes_salt = "opquweoijuqowieh"
class Aes():
    
    def __init__(self, key=aes_salt):
        self.key = key
        self.mode = AES.MODE_CBC

    def encrypt(self, text):
        cryptor = AES.new(self.key, self.mode, b'0000000000000000')
        length = 16
        count = len(text)
        if count < length:
            add = (length-count)
            text = text + ('\0' * add)
        elif count > length:
            add = (length-(count % length))
            text = text + ('\0' * add)
        self.ciphertext = cryptor.encrypt(text)
        return b2a_hex(self.ciphertext)

    def decrypt(self, text):
        cryptor = AES.new(self.key, self.mode, b'0000000000000000')
        plain_text = cryptor.decrypt(a2b_hex(text))
        return plain_text.rstrip('\0')

#rsa加解密,用于cookie的加解密
class Rsa():
    
    def __init__(self):
        self.random_generator = Random.new().read

    def gen_rsa_keys(self):
        rsa = RSA.generate(1024, self.random_generator)
        private_pem = rsa.exportKey()
        public_pem = rsa.publickey().exportKey()
        return (private_pem, public_pem)

    def crypto(self, public_key, text):
        rsakey = RSA.importKey(public_key)
        cipher = Cipher_pkcs1_v1_5.new(rsakey)
        crypto_text = base64.b64encode(cipher.encrypt(text))
        return crypto_text

    def decrypt(self, private_key, text):
        rsakey = RSA.importKey(private_key)
        cipher = Cipher_pkcs1_v1_5.new(rsakey)
        decrypt_text = cipher.decrypt(base64.b64decode(
            text), self.random_generator)
        return decrypt_text

if __name__ == '__main__':
    rsa = Rsa()
    aes = Aes()
    (pri,pub)=rsa.gen_rsa_keys()
    jm = rsa.crypto(pub, "pengng|||||123908123.123123")
    print rsa.decrypt(pri, jm)











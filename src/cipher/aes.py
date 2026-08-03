from Crypto.Cipher import AES

class Aes:
    def encrypt(self, plaintext: bytes, key:bytes)->bytes:
        if len(key) not in (16,24,32):
            raise ValueError("Key must be 16, 24 or 32 bytes long.")
        
        if len(plaintext) !=16:
            raise ValueError("Plaintext must be exactly 16 bytes.")
        
        cipher=AES.new(key,AES.MODE_ECB)
        ciphertext=cipher.encrypt(plaintext)
        
        return ciphertext
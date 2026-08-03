from src.cipher.aes import Aes

def test_encrypt():
    aes=Aes()
    
    key=bytes.fromhex("000102030405060708090A0B0C0D0E0F")
    
    plaintext= bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    
    ciphertext=aes.encrypt(plaintext,key)
    
    print("Ciphertext: ")
    print(ciphertext.hex())
from src.cipher.aes import Aes
from src.fault.injector import FaultInjector

def test_injector():
    aes=Aes()
    injector=FaultInjector()

    key=bytes.fromhex("000102030405060708090A0B0C0D0E0F")
        
    plaintext= bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    
    ciphertext=aes.encrypt(plaintext,key) 
    
    faultytext=injector.inject_byte_fault(ciphertext,5,97)
    
    print(f"Original:{ciphertext.hex()}\n")
    print(f"Faulty:{faultytext.hex()}")
    
    compare_bytes(ciphertext,faultytext)
    
def compare_bytes(original: bytes, faulty: bytes):
    for i, (o, f) in enumerate(zip(original, faulty)):
        if o != f:
            print(f"Byte {i}: {o:02X} -> {f:02X}")
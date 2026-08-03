from src.cipher import aes

class FaultInjector:
    def inject_byte_fault(self,ciphertext:bytes,byte_index:int,fault_value:int)->bytes:
        if not (0<=byte_index<len(ciphertext)):
            raise ValueError("Invalid byte index.")
        if not (0<=fault_value<=255):
            raise ValueError("Fault value must be 0-255.")
        
        data=bytearray(ciphertext)
        data[byte_index]^= fault_value
        
        return bytes(data)
    
    def inject_bit_fault(self,ciphertext: bytes,byte_index: int,bit_index: int)->bytes:
        if not (0 <= bit_index < 8):
            raise ValueError("Bit index must be 0-7.")

        data = bytearray(ciphertext)
        data[byte_index]^= (1<<bit_index)
        return bytes(data)
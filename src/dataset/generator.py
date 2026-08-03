from Crypto.Random import get_random_bytes
from src.cipher.aes import Aes
from src.fault.injector import FaultInjector
from src.models.sample import Sample
import random

class DatasetGenerator:
    def __init__(self):
        self.aes=Aes()
        self.injector=FaultInjector()
        
    def generate(self,samples=1000)->list:
        dataset=[]
        
        for _ in range(samples):
            plaintext=get_random_bytes(16)
            key=get_random_bytes(16)
            
            ciphertext=self.aes.encrypt(plaintext,key)
            
            fault_loc=random.randint(0,15)
            fault_value=random.randint(0,255)
            faultytext=self.injector.inject_byte_fault(ciphertext,fault_loc,fault_value)
            
            dataset.append(
                Sample(
                    ciphertext=ciphertext.hex(),
                    faultytext=faultytext.hex(),
                    fault_location=fault_loc,
                    fault_value=fault_value
                )
            )
            
        return dataset
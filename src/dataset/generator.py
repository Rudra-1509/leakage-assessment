from Crypto.Random import get_random_bytes
from src.cipher.aes import Aes
from src.fault.injector import FaultInjector
from src.models.sample import PaperSample, Sample
import random


class DatasetGenerator:
    def __init__(self):
        self.aes = Aes()
        self.injector = FaultInjector()

    def generate(self, samples=1000,fault_location=5,f1=0x01,f2=0x02) -> list:
        dataset = []
        key = get_random_bytes(16)

        for _ in range(samples):

            plaintext = get_random_bytes(16)
            ciphertext = self.aes.encrypt(plaintext, key)

            faulty_0 = self.injector.inject_byte_fault(
                ciphertext, byte_index=fault_location, fault_value=f1
            )
            dataset.append(PaperSample(ciphertext=faulty_0.hex(), label=0))

            faulty_1 = self.injector.inject_byte_fault(
                ciphertext, byte_index=fault_location, fault_value=f2
            )
            dataset.append(PaperSample(ciphertext=faulty_1.hex(), label=1))
            # fault_loc=random.randint(0,15)
            # fault_value=random.randint(0,255)
            # faultytext=self.injector.inject_byte_fault(ciphertext,fault_loc,fault_value)

            # dataset.append(
            #     Sample(
            #         ciphertext=ciphertext.hex(),
            #         faultytext=faultytext.hex(),
            #         fault_location=fault_loc,
            #         fault_value=fault_value
            #     )
            # )

        return dataset

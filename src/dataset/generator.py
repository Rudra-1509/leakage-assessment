from Crypto.Random import get_random_bytes

from src.cipher.manual_aes import ManualAES128
from src.models.sample import PaperSample


class DatasetGenerator:
    def generate(
        self,
        samples=1000,
        fault_location=5,
        f1=0x01,
        f2=0x02,
    ) -> list:

        dataset = []

        # Keep one key for the whole dataset for now.
        key = get_random_bytes(16)

        for _ in range(samples):

            plaintext = get_random_bytes(16)

            fault_0 = {
                "round": 9,
                "stage": "after_mix_columns",
                "byte_index": fault_location,
                "fault_value": f1,
            }

            fault_1 = {
                "round": 9,
                "stage": "after_mix_columns",
                "byte_index": fault_location,
                "fault_value": f2,
            }

            # Class 0
            aes_0 = ManualAES128(key)

            ciphertext_0 = aes_0.encrypt(
                plaintext,
                fault=fault_0,
            )

            dataset.append(
                PaperSample(
                    ciphertext=ciphertext_0.hex(),
                    label=0,
                )
            )

            # Class 1
            aes_1 = ManualAES128(key)

            ciphertext_1 = aes_1.encrypt(
                plaintext,
                fault=fault_1,
            )

            dataset.append(
                PaperSample(
                    ciphertext=ciphertext_1.hex(),
                    label=1,
                )
            )

        return dataset
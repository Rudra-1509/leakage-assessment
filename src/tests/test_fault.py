from src.cipher.manual_aes import ManualAES128


def test_fault():
    key = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f"
    )

    plaintext = bytes.fromhex(
        "00112233445566778899aabbccddeeff"
    )

    aes = ManualAES128(key)

    normal, normal_trace = aes.encrypt(
        plaintext,
        return_trace=True,
    )

    fault = {
        "round": 9,
        "stage": "after_mix_columns",
        "byte_index": 0,
        "fault_value": 0x01,
    }

    faulty, faulty_trace = aes.encrypt(
        plaintext,
        fault=fault,
        return_trace=True,
    )

    print("Normal :", normal.hex())
    print("Faulty :", faulty.hex())
    print("Same   :", normal == faulty)

    print("\nTrace entries around fault:")

    for entry in faulty_trace:
        if entry.round == 9:
            print(entry)
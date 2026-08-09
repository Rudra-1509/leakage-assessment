from src.dataset.generator import DatasetGenerator


def test_dataset():

    generator = DatasetGenerator()
    dataset = generator.generate(100)

    assert len(dataset) == 100

    for sample in dataset:

        original=bytes.fromhex(sample.ciphertext)
        faulty=bytes.fromhex(sample.faultytext)
        
        assert len(sample.ciphertext) == 32
        assert len(sample.faultytext) == 32

        assert 0 <= sample.fault_location < 16
        assert 0 <= sample.fault_value <= 255
        
        assert original[sample.fault_location] != faulty[sample.fault_location]

    print("Dataset validation passed!")
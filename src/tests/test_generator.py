from src.dataset.generator import DatasetGenerator

def test_generator():
    generator=DatasetGenerator()
    dataset= generator.generate(3)
    for sample in dataset:
        print(sample)
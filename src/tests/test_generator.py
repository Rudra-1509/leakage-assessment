from src.dataset.generator import DatasetGenerator

def test_generator():
    generator=DatasetGenerator()
    dataset= generator.generate(5,8,0x02,0x03)
    
    for sample in dataset:
        print(sample)
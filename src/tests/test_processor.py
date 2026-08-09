from src.dataset.generator import DatasetGenerator
from src.dataset.processor import DatasetProcessor


def test_processor():

    generator = DatasetGenerator()
    processor = DatasetProcessor()

    dataset = generator.generate(samples=5, fault_location=5, f1=0x01, f2=0x02)

    X, y = processor.prepare(dataset)

    print("X shape:", X.shape)
    print("y shape:", y.shape)

    print("\nFirst sample:")
    print(X[0])

    print("\nFirst label:")
    print(y[0])

    X = processor.normalize(X)
    print("X dtype:", X.dtype)
    print("Min:", X.min())
    print("Max:", X.max())
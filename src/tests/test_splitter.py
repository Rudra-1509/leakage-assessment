from src.dataset.generator import DatasetGenerator
from src.dataset.processor import DatasetProcessor
from src.dataset.splitter import DatasetSplitter


def test_splitter():

    generator = DatasetGenerator()
    processor = DatasetProcessor()
    splitter = DatasetSplitter()

    dataset = generator.generate(samples=50, fault_location=5, f1=0x01, f2=0x02)

    X, y = processor.prepare(dataset)
    X = processor.normalize(X)

    X_train, X_val, y_train, y_val = splitter.split(X, y)

    print("Training X:", X_train.shape)
    print("Training y:", y_train.shape)

    print("Validation X:", X_val.shape)
    print("Validation y:", y_val.shape)

    print("Training class 0:", (y_train == 0).sum())
    print("Training class 1:", (y_train == 1).sum())

    print("Validation class 0:", (y_val == 0).sum())
    print("Validation class 1:", (y_val == 1).sum())

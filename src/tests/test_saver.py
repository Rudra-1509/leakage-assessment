from src.dataset.generator import DatasetGenerator
from src.dataset.processor import DatasetProcessor
from src.dataset.saver import DatasetSaver


def test_saver():

    generator = DatasetGenerator()
    processor = DatasetProcessor()
    saver = DatasetSaver()

    dataset = generator.generate(100, fault_location=5, f1=0x01, f2=0x02)

    X, y = processor.prepare(dataset)
    #saver.save_json(dataset, "dataset.json")

    saver.save_numpy(X,y,"dataset.npz")
    print("Dataset saved successfully!")
    print("X shape:", X.shape)
    print("y shape:", y.shape)

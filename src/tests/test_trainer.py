from torch.utils.data import DataLoader

from src.dataset.generator import DatasetGenerator
from src.dataset.processor import DatasetProcessor
from src.dataset.splitter import DatasetSplitter
from src.models.dataset import LeakageDataset
from src.models.network import LeakageClassifier
from src.models.trainer import Trainer


def test_trainer():

    generator = DatasetGenerator()

    dataset = generator.generate(samples=500, fault_location=5, f1=0x01, f2=0x02)

    processor = DatasetProcessor()

    X, y = processor.prepare(dataset)
    X = processor.normalize(X)

    splitter = DatasetSplitter()

    X_train, X_val, y_train, y_val = splitter.split(X, y)

    train_dataset = LeakageDataset(X_train, y_train)
    val_dataset = LeakageDataset(X_val, y_val)

    train_loader = DataLoader(train_dataset, batch_size=32, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=32, shuffle=False)

    model = LeakageClassifier()
    trainer = Trainer(model)
    trainer.train(train_loader, epochs=10)
    accuracy = trainer.evaluate(val_loader)
    print(f"Validation Accuracy: {accuracy:.2%}")

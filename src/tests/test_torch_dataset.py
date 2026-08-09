from src.dataset.generator import DatasetGenerator
from src.dataset.processor import DatasetProcessor
from src.models.dataset import LeakageDataset

from torch.utils.data import DataLoader

def test_torch_dataset():

    generator = DatasetGenerator()
    processor = DatasetProcessor()

    dataset = generator.generate(samples=5, fault_location=5, f1=0x01, f2=0x02)

    X, y = processor.prepare(dataset)
    X = processor.normalize(X)

    torch_dataset = LeakageDataset(X, y)
    
    loader=DataLoader(torch_dataset,batch_size=4,shuffle=True)

    print("Dataset size:", len(torch_dataset))

    sample_x, sample_y = torch_dataset[0]

    print("X:", sample_x)
    print("X shape:", sample_x.shape)

    print("y:", sample_y)
    
    for batch_x, batch_y in loader:

        print("Batch X shape:", batch_x.shape)
        print("Batch y shape:", batch_y.shape)

        print("Batch X:")
        print(batch_x)

        print("Batch y:")
        print(batch_y)

        break

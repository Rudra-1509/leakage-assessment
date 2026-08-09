import json
from dataclasses import asdict
import numpy as np

class DatasetSaver:
    def save_json(self, dataset, filename):

        data = [asdict(sample) for sample in dataset]

        with open(filename, "w") as file:
            json.dump(data, file, indent=4)
            
    def save_numpy(self,X,y,filename):
        np.savez(filename,X,y)
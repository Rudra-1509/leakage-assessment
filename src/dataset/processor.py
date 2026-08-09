import numpy as np

class DatasetProcessor:
    def prepare(self,dataset):
        x=[]
        y=[]
        
        for sample in dataset:
            ciphertext=bytes.fromhex(sample.ciphertext)
            
            x.append(list(ciphertext))
            y.append(sample.label)
            
        return np.array(x),np.array(y)
    
    def normalize(self,X):
        return X.astype(np.float32) /255.0
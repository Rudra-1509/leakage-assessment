from sklearn.model_selection import train_test_split


class DatasetSplitter:

    def split(self, X, y, test_size=0.2):

        X_train, X_val, y_train, y_val = train_test_split(
            X, y, test_size=test_size, random_state=152, stratify=y
        )

        return X_train, X_val, y_train, y_val

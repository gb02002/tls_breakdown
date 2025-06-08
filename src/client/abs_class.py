from abc import abstractmethod, ABC

class ClientBase(ABC):
    def test_method(self):
        raise NotImplementedError

if __name__ == "__main__":
    cb = ClientBase()

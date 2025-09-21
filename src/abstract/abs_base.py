from abc import abstractmethod, ABC

class TLSConnection(ABC):
    """Responsible for all logic. Can be both Client and Server"""

    @abstractmethod
    def connect(self): ...

    @abstractmethod
    def accept(self): ...

    @abstractmethod
    def send(self, msg: str) -> bytes: ...

    @abstractmethod
    def recv(self, msg: bytes) -> str: ...


class Client_Server_Base(ABC):
    """I am not sure why it is here. Apparently wrapper for TLSConnection"""

    @abstractmethod
    def run_protocol(self): ...

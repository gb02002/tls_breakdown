import random

from src.abstract.abs_base import Client_Server_Base

P = 23 # prime
G = 5 # generator

class MockClient(Client_Server_Base):
    def __init__(self, name):
        self.name = name
        self.private = random.randint(1, P-2)
        self.public = pow(G, self.private, P)
        self.shared = None

    def compute_shared(self, other_public):
        self.shared = pow(other_public, self.private, P)

    def run_protocol(self):
        pass


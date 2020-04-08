from abc import ABC, abstractmethod
import asyncio

class Node(ABC):
    @abstractmethod
    async def deploy(self, module):
        pass

    @abstractmethod
    async def connect(self, from_module, from_output, to_module, to_input):
        pass

    @abstractmethod
    async def set_key(self, module, io_name, key):
        pass

    @abstractmethod
    async def call(self, module, entry, arg=None):
        pass

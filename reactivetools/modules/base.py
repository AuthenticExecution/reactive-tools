from abc import ABC, abstractmethod
import os
import logging
import sys
from .. import glob


class Error(Exception):
    pass


class Module(ABC):
    def __init__(self, name, node, old_node, priority, deployed, nonce,
                 attested, out_dir):
        """
        Generic attributes common to all Module subclasses

        Priority, deployed and nonce are used internally by the application

        ### Attributes ###
        name (str): name of the module
        node (XXXNode): *instance* of the Node class where the module belongs
        priority (int): priority of the module. For ordered deployment (can be None)
        deployed (bool): that indicates if the module has been deployed (can be None)
        nonce (int): nonce used in set_key to ensure freshness (can be None)
        """
        self.name = name
        self.node = node
        self.old_node = old_node
        self.priority = priority
        self.deployed = deployed
        self.nonce = 0 if nonce is None else nonce
        self.attested = attested

        self.connections = 0

        # create temp dir
        try:
            os.mkdir(os.path.join(glob.BUILD_DIR, out_dir))
        except FileExistsError:
            pass
        except:
            logging.error(f"Failed to create build dir for {name}")
            sys.exit(-1)

    @staticmethod
    @abstractmethod
    def load(mod_dict, node_obj, old_node_obj):
        """
        ### Description ###
        Creates a XXXModule object from a dict
        This should take all the information declared in the deployment descriptor
        and store it into the class as attributes.

        ### Parameters ###
        mod_dict (dict): dictionary containing the definition of the module
        node_obj (XXXNode): object where the module belongs to
        old_node_obj (XXXNode): object where the old module belongs to.
                                only used during module updates!

        ### Returns ###
        An instance of the XXXModule class
        """

    @abstractmethod
    def dump(self):
        """
        ### Description ###
        Creates a dict from the XXXModule object (opposite procedure wrt. load)
        This dict, saved in the output deployment descriptor, and serves two purposes:
        1) to provide the deployer some information (e.g., keys used)
        2) to give it as an input of subsequent runs of the application
        Hence, ideally load() and dump() should involve the same attributes

        ### Parameters ###
        self: Module object

        ### Returns ###
        `dict`: description of the object
        """

    @abstractmethod
    def clone(self):
        """
        ### Description ###
        Coroutine. Create a copy of the current module, but in a clean state,
        i.e., not deployed nor attested

        The

        ### Parameters ###
        self: Module object

        ### Returns ###
        `Module`: copy of the Module object
        """

    @abstractmethod
    async def build(self):
        """
        ### Description ###
        Coroutine. Create the binary file from sources

        ### Parameters ###
        self: Module object

        ### Returns ###
        `str`: path of the created binary file
        """

    @abstractmethod
    async def deploy(self):
        """
        ### Description ###
        Coroutine. Deploy a module to the corrisponding node

        Note: this coroutine should call the `deploy` coroutine in self.node,
        making sure that it can happen only once (e.g., using a flag)

        ### Parameters ###
        self: Module object

        ### Returns ###
        """

    @abstractmethod
    async def attest(self):
        """
        ### Description ###
        Coroutine. Attest a deployed module

        ### Parameters ###
        self: Module object

        ### Returns ###
        """

    @abstractmethod
    async def get_id(self):
        """
        ### Description ###
        Coroutine. Get the ID of the module

        The ID can be assigned in different ways, depending on the architecture.
        Should be unique on the node where the module is deployed.

        ### Parameters ###
        self: Module object

        ### Returns ###
        `int`: ID of the module
        """

    @abstractmethod
    async def get_input_id(self, input_):
        """
        ### Description ###
        Coroutine. Get the ID of the input passed as parameter

        This method should raise an error if the input does not exist

        ### Parameters ###
        self: Module object
        input (str): name of the input

        ### Returns ###
        `int`: ID of the input
        """

    @abstractmethod
    async def get_output_id(self, output):
        """
        ### Description ###
        Coroutine. Get the ID of the output passed as parameter

        This method should raise an error if the output does not exist

        ### Parameters ###
        self: Module object
        output (str): name of the output

        ### Returns ###
        `int`: ID of the output
        """

    @abstractmethod
    async def get_entry_id(self, entry):
        """
        ### Description ###
        Coroutine. Get the ID of the entry point passed as parameter

        This method should raise an error if the entry point does not exist

        ### Parameters ###
        self: Module object
        entry (str): name of the entry point

        ### Returns ###
        `int`: ID of the entry point
        """

    @abstractmethod
    async def get_key(self):
        """
        ### Description ###
        Coroutine. Get the module's key

        ### Parameters ###
        self: Module object

        ### Returns ###
        `bytes`: byte array of the key
        """

    @staticmethod
    @abstractmethod
    def get_supported_nodes():
        """
        ### Description ###
        Static method. Get a list of node classes where the module can be deployed

        e.g., SancusModule -> [SancusNode]

        ### Parameters ###

        ### Returns ###
        `list`: list of node classes that are supported by the XXXModule instance
        """

    @staticmethod
    @abstractmethod
    def get_supported_encryption():
        """
        ### Description ###
        Static method. Get a list of crypto libraries supported by the module
        The Encryption enum is defined in crypto.py

        e.g., SGXModule -> [Encryption.SPONGENT, Encryption.AES]

        ### Parameters ###

        ### Returns ###
        `list`: list of Encryption objects
        """

    @staticmethod
    @abstractmethod
    def get_default_encryption():
        """
        ### Description ###
        Static method. Get the preferred crypto library used by the module
        The Encryption enum is defined in crypto.py

        e.g., SGXModule -> Encryption.AES

        ### Parameters ###

        ### Returns ###
        `Encryption`: Encryption enum object
        """

    # Default implementation of some functions.
    # Override them in the subclasses if you need a different implementation.

    @staticmethod
    async def cleanup():
        """
        ### Description ###
        Static coroutine. Cleanup operations to do before the application terminates.

        ### Parameters ###

        ### Returns ###
        """

    async def get_request_id(self, request):
        """
        ### Description ###
        Coroutine. Get the ID of the request passed as parameter

        This method should raise an error if the request does not exist

        ### Parameters ###
        self: Module object
        request (str): name of the request

        ### Returns ###
        `int`: ID of the request
        """
        raise Error(f"Request/handler messages not supported for {self.__class__.__name__}")

    async def get_handler_id(self, handler):
        """
        ### Description ###
        Coroutine. Get the ID of the handler passed as parameter

        This method should raise an error if the handler does not exist

        ### Parameters ###
        self: Module object
        handler (str): name of the handler

        ### Returns ###
        `int`: ID of the handler
        """
        raise Error(f"Request/handler messages not supported for {self.__class__.__name__}")

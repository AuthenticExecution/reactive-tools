import asyncio
import logging
import binascii

from abc import ABC, abstractmethod

from reactivenet import ReactiveCommand, Message, CommandMessage, ReactiveEntrypoint

from .. import tools


class Error(Exception):
    pass


class Node(ABC):
    def __init__(self, name, ip_address, reactive_port, deploy_port, need_lock=False):
        """
        Generic attributes common to all Node subclasses

        ### Attributes ###
        name (str): name of the node
        ip_address (ip_address): IP of the node
        reactive_port (int): port where the event manager listens for events
        deploy_port (int): port where the event manager listens for new modules
        need_lock (bool): a bool indicating if the events need to be
                    delivered one at a time due to some limitations on the EM
        """

        self.name = name
        self.ip_address = ip_address
        self.reactive_port = reactive_port
        self.deploy_port = deploy_port

        if need_lock:
            self.__lock = asyncio.Lock()
        else:
            self.__lock = None

    @staticmethod
    @abstractmethod
    def load(node_dict):
        """
        ### Description ###
        Creates a XXXNode object from a dict
        This should take all the information declared in the deployment descriptor
        and store it into the class as attributes.

        ### Parameters ###
        node_dict (dict): dictionary containing the definition of the node

        ### Returns ###
        An instance of the XXXNode class
        """

    @abstractmethod
    def dump(self):
        """
        ### Description ###
        Creates a dict from the XXXNode object (opposite procedure wrt. load)
        This dict, saved in the output deployment descriptor, and serves two purposes:
        1) to provide the deployer some information (e.g., keys used)
        2) to give it as an input of subsequent runs of the application
        Hence, ideally load() and dump() should involve the same attributes

        ### Parameters ###
        self: Node object

        ### Returns ###
        `dict`: description of the object
        """

    @abstractmethod
    async def deploy(self, module):
        """
        ### Description ###
        Coroutine. Deploy a module to the node

        How this is done depends on the architecture, in general the binary of the
        module must be sent to the Event Manager with a special event on the deploy_port

        *NOTE*: this coroutine should check if module has already been deployed
                (doing nothing if this is the case), and set module.deployed to True
                after deployment

        ### Parameters ###
        self: Node object
        module (XXXModule): module object to deploy

        ### Returns ###
        """

    @abstractmethod
    async def set_key(self, module, conn_id, conn_io, encryption, key):
        """
        ### Description ###
        Coroutine. Sets the key of a specific connection

        How this is done depends on the architecture, in general the key and other args
        must be sent to the Event Manager with a special event on the reactive_port

        conn_io indicates which input/output/request/handler is involved in the connection
        encryption indicates which crypto library is used in this connection

        *NOTE*: this coroutine should use module.nonce as part of associated data
                and increment it if everything went well

        ### Parameters ###
        self: Node object
        module (XXXModule): module where the key is being set
        conn_id (int): ID of the connection
        conn_io (ConnectionIO): object of the ConnectionIO class (see connection.py)
        encryption (Encryption): object of the Encryption class (see crypto.py)
        key (bytes): connection key

        ### Returns ###
        """

    # Default implementation of some functions.
    # Override them in the subclasses if you need a different implementation.

    @staticmethod
    async def cleanup():
        """
        ### Description ###
        Static coroutine. Cleanup operations to do before the application terminates

        ### Parameters ###

        ### Returns ###
        """

    async def connect(self, to_module, conn_id):
        """
        ### Description ###
        Coroutine. Inform the EM of the source module that a new connection has
        been established, so that events can be correctly forwared to the recipient

        ### Parameters ###
        self: Node object
        to_module (XXXModule): destination module
        conn_id (int): ID of the connection

        ### Returns ###
        """
        module_id = await to_module.get_id()

        payload = tools.pack_int16(conn_id) + \
            tools.pack_int16(module_id) + \
            tools.pack_int8(int(to_module.node is self)) + \
            tools.pack_int16(to_module.node.reactive_port) + \
            to_module.node.ip_address.packed

        command = CommandMessage(ReactiveCommand.Connect,
                                 Message(payload),
                                 self.ip_address,
                                 self.reactive_port)

        await self._send_reactive_command(
            command,
            log=f'Connecting id {conn_id} to {to_module.name}')

    async def call(self, module, entry, arg=None, output=None):
        """
        ### Description ###
        Coroutine. Call the entry point of a module

        ### Parameters ###
        self: Node object
        to_module (XXXModule): target module
        entry (str): name of the entry point to call
        arg (bytes): argument to pass as a byte array (can be None)

        ### Returns ###
        """
        assert module.node is self

        module_id, entry_id = \
            await asyncio.gather(module.get_id(), module.get_entry_id(entry))

        payload = tools.pack_int16(module_id) + \
            tools.pack_int16(entry_id) + \
            (b'' if arg is None else arg)

        command = CommandMessage(ReactiveCommand.Call,
                                 Message(payload),
                                 self.ip_address,
                                 self.reactive_port)

        response = await self._send_reactive_command(
            command,
            log=f"Sending call command to {module.name}:{entry}" \
                f" ({module_id}:{entry_id}) on {self.name}"
        )

        if not response.ok():
            logging.error(f"Received error code {str(response.code)}")
            return

        if output is None:
            pl = binascii.hexlify(response.message.payload).decode('ascii')
            logging.info(f"Response: \"{pl}\"")
        else:
            with open(output, "wb") as f:
                f.write(response.message.payload)

    async def output(self, connection, arg=None):
        """
        ### Description ###
        Coroutine. Trigger the 'output' event of a direct connection

        ### Parameters ###
        self: Node object
        connection (Connection): connection object
        arg (bytes): argument to pass as a byte array (can be None)

        ### Returns ###
        """
        assert connection.to_module.node is self

        module_id = await connection.to_module.get_id()

        if arg is None:
            data = b''
        else:
            data = arg

        cipher = await connection.encryption.encrypt(connection.key,
                                                     tools.pack_int16(connection.nonce), data)

        payload = tools.pack_int16(module_id) + \
            tools.pack_int16(connection.id) + \
            cipher

        command = CommandMessage(ReactiveCommand.RemoteOutput,
                                 Message(payload),
                                 self.ip_address,
                                 self.reactive_port)

        await self._send_reactive_command(
            command,
            log=f"Sending handle_output command of connection" \
                f" {connection.id}:{connection.name} to {connection.to_module.name}" \
                f" on {self.name}"
        )

    async def request(self, connection, arg=None, output=None):
        """
        ### Description ###
        Coroutine. Trigger the 'request' event of a direct connection

        ### Parameters ###
        self: Node object
        connection (Connection): connection object
        arg (bytes): argument to pass as a byte array (can be None)

        ### Returns ###
        """
        assert connection.to_module.node is self

        module_id = await connection.to_module.get_id()

        if arg is None:
            data = b''
        else:
            data = arg

        cipher = await connection.encryption.encrypt(connection.key,
                                                     tools.pack_int16(connection.nonce), data)

        payload = tools.pack_int16(module_id) + \
            tools.pack_int16(connection.id) + \
            cipher

        command = CommandMessage(ReactiveCommand.RemoteRequest,
                                 Message(payload),
                                 self.ip_address,
                                 self.reactive_port)

        response = await self._send_reactive_command(
            command,
            log=f"Sending handle_request command of connection" \
                f" {connection.id}:{connection.name} to" \
                f" {connection.to_module.name} on {self.name}"
        )

        if not response.ok():
            logging.error(f"Received error code {str(response.code)}")
            return

        resp_encrypted = response.message.payload
        plaintext = await connection.encryption.decrypt(connection.key,
                                                        tools.pack_int16(
                                                            connection.nonce + 1),
                                                        resp_encrypted)

        if output is None:
            logging.info(f"Response: \"{binascii.hexlify(plaintext).decode('ascii')}\"")
        else:
            with open(output, "wb") as f:
                f.write(plaintext)

    async def register_entrypoint(self, module, entry, frequency):
        """
        ### Description ###
        Coroutine. Register an entry point for periodic tasks

        ### Parameters ###
        self: Node object
        module (XXXModule): target module
        entry (str): entry point to call
        frequency (int): desired frequency of which the entry point will be called

        ### Returns ###
        """
        assert module.node is self
        module_id, entry_id = \
            await asyncio.gather(module.get_id(), module.get_entry_id(entry))

        payload = tools.pack_int16(module_id) + \
            tools.pack_int16(entry_id) + \
            tools.pack_int32(frequency)

        command = CommandMessage(ReactiveCommand.RegisterEntrypoint,
                                 Message(payload),
                                 self.ip_address,
                                 self.reactive_port)

        await self._send_reactive_command(
            command,
            log=f"Sending RegisterEntrypoint command of" \
                f" {module.name}:{entry} ({module_id}:{entry_id}) on {self.name}"
        )

    async def disable_module(self, module):
        """
        ### Description ###
        Coroutine. Sends a command to disable the module

        ### Parameters ###
        self: Node object
        module (XXXModule): target module

        ### Returns ###
        """
        assert module.old_node is self
        module_id, module_key = \
            await asyncio.gather(module.get_id(), module.get_key())

        ad = tools.pack_int16(module.nonce)
        module.nonce += 1

        cipher = await module.get_default_encryption().encrypt(module_key, ad, ad)

        # The payload format is [sm_id, entry_id, 16 bit nonce, tag]
        payload = tools.pack_int16(module_id) + \
            tools.pack_int16(ReactiveEntrypoint.Disable) + \
            ad + \
            cipher

        command = CommandMessage(ReactiveCommand.Call,
                                 Message(payload),
                                 self.ip_address,
                                 self.reactive_port)

        await self._send_reactive_command(
            command,
            log=f'Sending disable command to module {module.name}'
        )

    async def reset(self):
        """
        ### Description ###
        Coroutine. Reset node, deleting all running modules and connections

        ### Parameters ###
        self: Node object

        ### Returns ###
        """
        command = CommandMessage(ReactiveCommand.Reset,
                                 Message(),
                                 self.ip_address,
                                 self.reactive_port)

        await self._send_reactive_command(
            command,
            log=f'Resetting node {self.name}')

    async def _send_reactive_command(self, command, log=None):
        """
        ### Description ###
        Coroutine. Wrapper to __send_reactive_command (see below)

        ### Parameters ###
        self: Node object
        command (ReactiveCommand): command to send to the node
        log (str): optional text message printed to stdout (can be None)

        ### Returns ###
        """
        if self.__lock is not None:
            async with self.__lock:
                return await self.__send_reactive_command(command, log)
        else:
            return await self.__send_reactive_command(command, log)

    @staticmethod
    async def __send_reactive_command(command, log):
        """
        ### Description ###
        Static coroutine. Helper function used to send a ReactiveCommand message to the node

        ReactiveCommand: defined in reactivenet: https://github.com/gianlu33/reactive-net

        ### Parameters ###
        command (ReactiveCommand): command to send to the node
        log (str): optional text message printed to stdout (can be None)

        ### Returns ###
        """
        if log is not None:
            logging.info(log)

        if command.has_response():
            response = await command.send_wait()
            if not response.ok():
                raise Error(f"Reactive command {str(command.code)} failed " \
                            f"with code {str(response.code)}")
            return response

        await command.send()
        return None

import asyncio
import logging
import os
import json
import rustsgxgen

from .base import Module

from ..nodes import NativeNode
from .. import tools
from .. import glob
from ..crypto import Encryption
from ..dumpers import *
from ..loaders import *
from ..manager import get_manager

BUILD_APP = "cargo build {} {} --manifest-path={}/Cargo.toml"


class Object():
    pass


class Error(Exception):
    pass


class NativeModule(Module):
    def __init__(self, name, node, priority, deployed, nonce, attested, features,
                 id_, binary, key, data, folder, port):
        self.out_dir = os.path.join(glob.BUILD_DIR, "native-{}".format(folder))
        super().__init__(name, node, priority, deployed, nonce, attested, self.out_dir)

        self.__generate_fut = tools.init_future(data, key)
        self.__build_fut = tools.init_future(binary)

        self.features = [] if features is None else features
        self.id = id_ if id_ is not None else node.get_module_id()
        self.port = port or self.node.reactive_port + self.id
        self.folder = folder

    @staticmethod
    def load(mod_dict, node_obj):
        name = mod_dict['name']
        node = node_obj
        priority = mod_dict.get('priority')
        deployed = mod_dict.get('deployed')
        nonce = mod_dict.get('nonce')
        attested = mod_dict.get('attested')
        features = mod_dict.get('features')
        id_ = mod_dict.get('id')
        binary = parse_file_name(mod_dict.get('binary'))
        key = parse_key(mod_dict.get('key'))
        data = mod_dict.get('data')
        folder = mod_dict.get('folder') or name
        port = mod_dict.get('port')

        return NativeModule(name, node, priority, deployed, nonce, attested,
                            features, id_, binary, key, data, folder, port)

    def dump(self):
        return {
            "type": "native",
            "name": self.name,
            "node": self.node.name,
            "priority": self.priority,
            "deployed": self.deployed,
            "nonce": self.nonce,
            "attested": self.attested,
            "features": self.features,
            "id": self.id,
            "binary": dump(self.binary) if self.deployed else None,
            # For native, key is generated at compile time
            "key": dump(self.key) if self.deployed else None,
            "data": dump(self.data) if self.deployed else None,
            "folder": self.folder,
            "port": self.port
        }

    # --- Properties --- #

    @property
    async def data(self):
        data, _key = await self.generate_code()
        return data

    @property
    async def inputs(self):
        data = await self.data
        return data["inputs"]

    @property
    async def outputs(self):
        data = await self.data
        return data["outputs"]

    @property
    async def entrypoints(self):
        data = await self.data
        return data["entrypoints"]

    @property
    async def handlers(self):
        data = await self.data
        return data["handlers"]

    @property
    async def requests(self):
        data = await self.data
        return data["requests"]

    @property
    async def key(self):
        _data, key = await self.generate_code()
        return key

    @property
    async def binary(self):
        return await self.build()

    # --- Implement abstract methods --- #

    async def build(self):
        if self.__build_fut is None:
            self.__build_fut = asyncio.ensure_future(self.__build())

        return await self.__build_fut

    async def deploy(self):
        await self.node.deploy(self)

    async def attest(self):
        if get_manager() is not None:
            await self.__attest_manager()
        else:
            await self.key

        self.attested = True

    async def get_id(self):
        return self.id

    async def get_input_id(self, input_):
        if isinstance(input_, int):
            return input_

        inputs = await self.inputs

        if input_ not in inputs:
            raise Error("Input not present in inputs")

        return inputs[input_]

    async def get_output_id(self, output):
        if isinstance(output, int):
            return output

        outputs = await self.outputs

        if output not in outputs:
            raise Error("Output not present in outputs")

        return outputs[output]

    async def get_entry_id(self, entry):
        try:
            return int(entry)
        except:
            entrypoints = await self.entrypoints

            if entry not in entrypoints:
                raise Error("Entry not present in entrypoints")

            return entrypoints[entry]

    async def get_request_id(self, request):
        if isinstance(request, int):
            return request

        requests = await self.requests

        if request not in requests:
            raise Error("Request not present in requests")

        return requests[request]

    async def get_handler_id(self, handler):
        if isinstance(handler, int):
            return handler

        handlers = await self.handlers

        if handler not in handlers:
            raise Error("Handler not present in handlers")

        return handlers[handler]

    async def get_key(self):
        return await self.key

    @staticmethod
    def get_supported_nodes():
        return [NativeNode]

    @staticmethod
    def get_supported_encryption():
        return [Encryption.AES, Encryption.SPONGENT]

    @staticmethod
    def get_default_encryption():
        return Encryption.AES

    # --- Static methods --- #

    # --- Others --- #

    async def generate_code(self):
        if self.__generate_fut is None:
            self.__generate_fut = asyncio.ensure_future(self.__generate_code())

        return await self.__generate_fut

    async def __generate_code(self):
        args = Object()

        args.input = self.folder
        args.output = self.out_dir
        args.moduleid = self.id
        args.emport = self.node.deploy_port
        args.runner = rustsgxgen.Runner.NATIVE
        args.spkey = None
        args.print = None

        data, key = rustsgxgen.generate(args)
        logging.info("Generated code for module {}".format(self.name))

        return data, key

    async def __build(self):
        await self.generate_code()

        release = "--release" if glob.get_build_mode() == glob.BuildMode.RELEASE else ""
        features = "--features " + \
            " ".join(self.features) if self.features else ""

        cmd = BUILD_APP.format(release, features, self.out_dir).split()
        await tools.run_async(*cmd)

        # TODO there might be problems with two (or more) modules built from
        #      the same source code but with different features. Since the
        #      working dir is the same (for caching reasons) there might be some
        #      problems when these SMs are built at the same time.
        #      Find a way to solve this issue.
        binary = os.path.join(self.out_dir,
                              "target", glob.get_build_mode().to_str(), self.folder)

        logging.info("Built module {}".format(self.name))
        return binary

    async def __attest_manager(self):
        data = {
            "id": self.id,
            "name": self.name,
            "host": str(self.node.ip_address),
            "port": self.port,
            "em_port": self.node.reactive_port,
            "key": list(await self.key)
        }
        data_file = tools.create_tmp(suffix=".json")
        with open(data_file, "w") as f:
            json.dump(data, f)

        args = "--config {} --request attest-native --data {}".format(
            get_manager().config, data_file).split()
        out, _ = await tools.run_async_output(glob.ATTMAN_CLI, *args)
        key_arr = eval(out)  # from string to array
        key = bytes(key_arr)  # from array to bytes

        if await self.key != key:
            raise Error(
                "Received key is different from {} key".format(self.name))

        logging.info("Done Remote Attestation of {}. Key: {}".format(
            self.name, key_arr))

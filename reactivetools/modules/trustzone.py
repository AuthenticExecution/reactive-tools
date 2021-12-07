import logging
import asyncio
import hashlib
import json
import os
import uuid
import tzcodegen

from .base import Module
from ..nodes import TrustZoneNode
from .. import tools
from .. import glob
from ..crypto import Encryption
from ..dumpers import *
from ..loaders import *
from ..manager import get_manager


class Error(Exception):
    pass

class Object():
    pass

COMPILER = "CROSS_COMPILE=arm-linux-gnueabihf-"
PLATFORM = "PLATFORM=vexpress-qemu_virt"
DEV_KIT = "TA_DEV_KIT_DIR=/optee/optee_os/out/arm/export-ta_arm32"
BUILD_CMD = "make -C {{}} {} {} {} {{}} O={{}}".format(
    COMPILER, PLATFORM, DEV_KIT)


class TrustZoneModule(Module):
    def __init__(self, name, node, priority, deployed, nonce, attested,
                 binary, id_, uUID, key, data, folder):
        self.out_dir = os.path.join(
            glob.BUILD_DIR, "trustzone-{}".format(name))
        super().__init__(name, node, priority, deployed, nonce, attested, self.out_dir)

        self.id = id_ if id_ is not None else node.get_module_id()
        self.folder = folder
    
        self.uuid_for_MK = ""

        self.__generate_fut = tools.init_future(data , uUID)
        self.__build_fut = tools.init_future(binary)
        self.__key_fut = tools.init_future(key)
        self.__attest_fut = tools.init_future(attested if attested else None)

    @staticmethod
    def load(mod_dict, node_obj):
        name = mod_dict['name']
        node = node_obj
        priority = mod_dict.get('priority')
        deployed = mod_dict.get('deployed')
        nonce = mod_dict.get('nonce')
        attested = mod_dict.get('attested')
        binary = mod_dict.get('binary')
        id_ = mod_dict.get('id')
        uUID = mod_dict.get('uuid')
        key = parse_key(mod_dict.get('key'))
        data = mod_dict.get('data')
        folder = mod_dict.get('folder') or name
        return TrustZoneModule(name, node, priority, deployed, nonce, attested,
                               binary, id_, uUID, key, data, folder)
    
    def dump(self):
        return {
            "type": "trustzone",
            "name": self.name,
            "node": self.node.name,
            "priority": self.priority,
            "deployed": self.deployed,
            "nonce": self.nonce,
            "attested": self.attested,
            "binary": dump(self.binary) if self.deployed else None,
            "id": self.id,
            "uuid": dump(self.uUID) if self.deployed else None,
            "key": dump(self.key) if self.deployed else None,
            "data": dump(self.data) if self.deployed else None,
            "folder": self.folder
        }
    
    # --- Properties --- #
    
    @property
    async def uUID(self):
        _,uUID = await self.generate_code()
        return uUID

    @property
    async def data(self):
        data, _ = await self.generate_code()
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
    async def binary(self):
        return await self.build()

    @property
    async def key(self):
        if self.__key_fut is None:
            self.__key_fut = asyncio.ensure_future(self.__calculate_key())

        return await self.__key_fut

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
            if self.__attest_fut is None:
                self.__attest_fut = asyncio.ensure_future(
                    self.node.attest(self))

            await self.__attest_fut

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
        if entry.isnumeric():
            return int(entry)

        entrypoints = await self.entrypoints

        if entry not in entrypoints:
            raise Error("Entry not present in entrypoints")

        return entrypoints[entry]

    async def get_key(self):
        return await self.key

    @staticmethod
    def get_supported_nodes():
        return [TrustZoneNode]

    @staticmethod
    def get_supported_encryption():
        return [Encryption.AES, Encryption.SPONGENT]

    # --- Other methods --- #
    async def generate_code(self):
        if self.__generate_fut is None:
            self.__generate_fut = asyncio.ensure_future(self.__generate_code())

        return await self.__generate_fut

    async def __generate_code(self):
        args = Object()

        args.input = self.folder
        args.output = self.out_dir
        
        args.print = None

        data, uUID = tzcodegen.generate(args)
        logging.info("Generated code for module {}".format(self.name))
        
        return data, uUID

    async def __build(self):
        await self.generate_code()

        temp =  await self.uUID

        hexa = '%032x' % (temp)
        self.uuid_for_MK = '%s-%s-%s-%s-%s' % (
            hexa[:8], hexa[8:12], hexa[12:16], hexa[16:20], hexa[20:])

        binary_name = "BINARY=" + self.uuid_for_MK
        #cmd = BUILD_CMD.format(self.files_dir, self.name, binary_name, self.out_dir)
        cmd = BUILD_CMD.format(self.out_dir, binary_name, self.out_dir)

        await tools.run_async_shell(cmd)

        binary = "{}/{}.ta".format(self.out_dir, self.uuid_for_MK)

        return binary
 
    async def __calculate_key(self):
        binary = await self.binary
        node_key = self.node.node_key

        with open(binary, 'rb') as f:
            # first 20 bytes are the header (struct shdr), next 32 bytes are the hash
            module_hash = f.read(52)[20:]

        key_size = Encryption.AES.get_key_size()
        if key_size > 32:
            raise Error(
                "SHA256 cannot compute digests with length {}".format(key_size))

        return hashlib.sha256(node_key + module_hash).digest()[:key_size]

    async def __attest_manager(self):
        data = {
            "id": self.id,
            "name": self.name,
            "host": str(self.node.ip_address),
            "port": self.node.reactive_port,
            "em_port": self.node.reactive_port,
            "key": list(await self.key)
        }
        data_file = tools.create_tmp(suffix=".json")
        with open(data_file, "w") as f:
            json.dump(data, f)

        args = "--config {} --request attest-trustzone --data {}".format(
            get_manager().config, data_file).split()
        out, _ = await tools.run_async_output(glob.ATTMAN_CLI, *args)
        key_arr = eval(out)  # from string to array
        key = bytes(key_arr)  # from array to bytes

        if await self.key != key:
            raise Error(
                "Received key is different from {} key".format(self.name))

        logging.info("Done Remote Attestation of {}. Key: {}".format(
            self.name, key_arr))
        self.attested = True

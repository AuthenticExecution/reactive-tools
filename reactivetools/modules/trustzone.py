import logging
import asyncio
import binascii
import hashlib
import json
import os

from .base import Module
from ..nodes import TrustZoneNode
from .. import tools
from .. import glob
from ..crypto import Encryption
from ..dumpers import *
from ..loaders import *

class Error(Exception):
    pass

COMPILER  = "CROSS_COMPILE=arm-linux-gnueabihf-"
PLATFORM  = "PLATFORM=vexpress-qemu_virt"
DEV_KIT   = "TA_DEV_KIT_DIR=/optee/optee_os/out/arm/export-ta_arm32"
BUILD_CMD = "make -C {{}}/{{}} {} {} {} {{}} O={{}}".format(COMPILER, PLATFORM, DEV_KIT)

class TrustZoneModule(Module):
    def __init__(self, name, node, priority, deployed, nonce, attested, files_dir,
                    binary, id, uuid, key, inputs, outputs, entrypoints):
        self.out_dir = os.path.join(glob.BUILD_DIR, "trustzone-{}".format(name))
        super().__init__(name, node, priority, deployed, nonce, attested, self.out_dir)

        self.files_dir = files_dir
        self.id = id
        self.uuid = uuid
        self.inputs =  inputs
        self.outputs =  outputs
        self.entrypoints =  entrypoints

        self.uuid_for_MK = ""

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
        files_dir = mod_dict.get('files_dir')
        binary = mod_dict.get('binary')
        id = mod_dict.get('id')
        uuid = mod_dict.get('uuid')
        key = parse_key(mod_dict.get('key'))
        inputs = mod_dict.get('inputs')
        outputs = mod_dict.get('outputs')
        entrypoints = mod_dict.get('entrypoints')
        return TrustZoneModule(name, node, priority, deployed, nonce, attested, files_dir,
                                binary, id, uuid, key, inputs, outputs, entrypoints)


    def dump(self):
        return {
            "type": "trustzone",
            "name": self.name,
            "node": self.node.name,
            "priority": self.priority,
            "deployed": self.deployed,
            "nonce": self.nonce,
            "attested": self.attested,
            "files_dir": self.files_dir,
            "binary": dump(self.binary) if self.deployed else None,
            "id": self.id,
            "uuid": self.uuid,
            "key": dump(self.key) if self.deployed else None,
            "inputs":self.inputs,
            "outputs":self.outputs,
            "entrypoints":self.entrypoints
        }

    # --- Properties --- #

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
        if glob.get_att_man():
            await self.__attest_manager()
        else:
            if self.__attest_fut is None:
                self.__attest_fut = asyncio.ensure_future(self.node.attest(self))

            await self.__attest_fut


    async def get_id(self):
        return self.id


    async def get_input_id(self, input):
        if isinstance(input, int):
            return input

        inputs = self.inputs

        if input not in inputs:
            raise Error("Input not present in inputs")

        return inputs[input]


    async def get_output_id(self, output):
        if isinstance(output, int):
            return output

        outputs = self.outputs

        if output not in outputs:
            raise Error("Output not present in outputs")

        return outputs[output]


    async def get_entry_id(self, entry):
        if entry.isnumeric():
            return int(entry)

        entrypoints = self.entrypoints

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

    async def __build(self):
        hex = '%032x' % (self.uuid)
        self.uuid_for_MK = '%s-%s-%s-%s-%s' % (hex[:8], hex[8:12], hex[12:16], hex[16:20], hex[20:])

        binary_name = "BINARY=" + self.uuid_for_MK
        cmd = BUILD_CMD.format(self.files_dir, self.name, binary_name, self.out_dir)

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
            raise Error("SHA256 cannot compute digests with length {}".format(key_size))

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
                    self.manager.config, data_file).split()
        out, _ = await tools.run_async_output(glob.ATTMAN_CLI, *args)
        key_arr = eval(out) # from string to array
        key = bytes(key_arr) # from array to bytes

        if await self.key != key:
            raise Error("Received key is different from {} key".format(self.name))

        logging.info("Done Remote Attestation of {}. Key: {}".format(self.name, key_arr))
        self.attested = True

import asyncio
import logging
import os
import rustsgxgen

from .base import Module

from ..nodes import SGXNode
from .. import tools
from .. import glob
from ..crypto import Encryption
from ..dumpers import *
from ..loaders import *
from ..manager import get_manager
from ..descriptor import DescriptorType

# Apps
ATTESTER = "sgx-attester"
ROOT_CA_URL = "https://certificates.trustedservices.intel.com/Intel_SGX_Attestation_RootCA.pem"

# SGX build/sign
SGX_TARGET = "x86_64-fortanix-unknown-sgx"
BUILD_APP = "cargo build {{}} {{}} --target={} --manifest-path={{}}/Cargo.toml".format(
    SGX_TARGET)
CONVERT_SGX = "ftxsgx-elf2sgxs {} --heap-size 0x400000 --stack-size 0x400000 --threads 4 {}"
SIGN_SGX = "sgxs-sign --key {} {} {} {}" # use default values


class Object():
    pass


class Error(Exception):
    pass


class SGXModule(Module):
    sp_lock = asyncio.Lock()

    def __init__(self, name, node, old_node, priority, deployed, nonce, attested,
                 vendor_key, ra_settings, features, id_, binary, key, sgxs,
                 signature, data, folder, port):
        self.out_dir = os.path.join(glob.BUILD_DIR, f"sgx-{folder}")
        super().__init__(name, node, old_node, priority, deployed, nonce,
                         attested, self.out_dir)

        self.__generate_fut = tools.init_future(data)
        self.__build_fut = tools.init_future(binary)
        self.__convert_sign_fut = tools.init_future(sgxs, signature)
        self.__attest_fut = tools.init_future(key)
        self.__sp_keys_fut = asyncio.ensure_future(self.__generate_sp_keys())

        self.key = key
        self.vendor_key = vendor_key
        self.ra_settings = ra_settings
        self.features = [] if features is None else features
        self.id = id_ if id_ is not None else node.get_module_id()
        self.port = port or self.node.reactive_port + self.id
        self.folder = folder

    @staticmethod
    def load(mod_dict, node_obj, old_node_obj):
        name = mod_dict['name']
        node = node_obj
        old_node = old_node_obj
        priority = mod_dict.get('priority')
        deployed = mod_dict.get('deployed')
        nonce = mod_dict.get('nonce')
        attested = mod_dict.get('attested')
        vendor_key = parse_file_name(mod_dict['vendor_key'])
        settings = parse_file_name(mod_dict['ra_settings'])
        features = mod_dict.get('features')
        id_ = mod_dict.get('id')
        binary = parse_file_name(mod_dict.get('binary'))
        key = parse_key(mod_dict.get('key'))
        sgxs = parse_file_name(mod_dict.get('sgxs'))
        signature = parse_file_name(mod_dict.get('signature'))
        data = mod_dict.get('data')
        folder = mod_dict.get('folder') or name
        port = mod_dict.get('port')

        return SGXModule(name, node, old_node, priority, deployed, nonce,
                         attested, vendor_key, settings, features, id_, binary,
                         key, sgxs, signature, data, folder, port)

    def dump(self):
        return {
            "type": "sgx",
            "name": self.name,
            "node": self.node.name,
            "old_node": self.old_node.name,
            "priority": self.priority,
            "deployed": self.deployed,
            "nonce": self.nonce,
            "attested": self.attested,
            "vendor_key": self.vendor_key,
            "ra_settings": self.ra_settings,
            "features": self.features,
            "id": self.id,
            "binary": dump(self.binary) if self.deployed else None,
            "sgxs": dump(self.sgxs) if self.deployed else None,
            "signature": dump(self.sig) if self.deployed else None,
            "key": dump(self.key) if self.attested else None,
            "data": dump(self.data) if self.deployed else None,
            "folder": self.folder,
            "port": self.port
        }

    def clone(self):
        return SGXModule(
            self.name,
            self.node,
            self.old_node,
            self.priority,
            None,
            None,
            None,
            self.vendor_key,
            self.ra_settings,
            self.features,
            None,
            None,
            None,
            None,
            None,
            None,
            self.folder,
            None
        )

    # --- Properties --- #

    @property
    async def data(self):
        data = await self.generate_code()
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
    async def binary(self):
        return await self.build()

    @property
    async def sgxs(self):
        if self.__convert_sign_fut is None:
            self.__convert_sign_fut = asyncio.ensure_future(
                self.__convert_sign())

        sgxs, _ = await self.__convert_sign_fut

        return sgxs

    @property
    async def sig(self):
        if self.__convert_sign_fut is None:
            self.__convert_sign_fut = asyncio.ensure_future(
                self.__convert_sign())

        _, sig = await self.__convert_sign_fut

        return sig

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
                self.__attest_fut = asyncio.ensure_future(self.__attest())

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
        return self.key

    @staticmethod
    def get_supported_nodes():
        return [SGXNode]

    @staticmethod
    def get_supported_encryption():
        return [Encryption.AES, Encryption.SPONGENT]

    @staticmethod
    def get_default_encryption():
        return Encryption.AES

    # --- Static methods --- #

    @staticmethod
    async def cleanup():
        pass

    # --- Others --- #

    async def get_ra_sp_pub_key(self):
        pub, _, _ = await self.__sp_keys_fut

        return pub

    async def get_ra_sp_priv_key(self):
        _, priv, _ = await self.__sp_keys_fut

        return priv

    async def get_ias_root_certificate(self):
        _, _, cert = await self.__sp_keys_fut

        return cert

    async def generate_code(self):
        if self.__generate_fut is None:
            self.__generate_fut = asyncio.ensure_future(self.__generate_code())

        return await self.__generate_fut

    async def __generate_code(self):
        args = Object()
        man = get_manager()

        args.input = self.folder
        args.output = self.out_dir
        args.moduleid = self.id
        args.emport = self.node.deploy_port
        args.runner = rustsgxgen.Runner.SGX
        args.spkey = await man.get_sp_pubkey() \
            if man is not None else await self.get_ra_sp_pub_key()
        args.print = None

        data, _ = rustsgxgen.generate(args)
        logging.info(f"Generated code for module {self.name}")

        return data

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
        binary = os.path.join(self.out_dir, "target", SGX_TARGET,
                              glob.get_build_mode().to_str(), self.folder)

        logging.info(f"Built module {self.name}")

        return binary

    async def __convert_sign(self):
        binary = await self.binary
        debug = "--debug" if glob.get_build_mode() == glob.BuildMode.DEBUG else ""

        sgxs = f"{binary}.sgxs"

        # use this format for the file names to deal with multiple SMs built
        # from the same source code, but with different vendor keys
        sig = f"{binary}-{self.name}.sig"

        cmd_convert = CONVERT_SGX.format(binary, debug).split()
        cmd_sign = SIGN_SGX.format(self.vendor_key, sgxs, sig, debug).split()

        await tools.run_async(*cmd_convert)
        await tools.run_async(*cmd_sign)

        logging.info(f"Converted & signed module {self.name}")

        return sgxs, sig

    async def __attest(self):
        input_arg = {}
        input_arg["sp_privkey"] = await self.get_ra_sp_priv_key()
        input_arg["ias_cert"] = await self.get_ias_root_certificate()
        input_arg["enclave_settings"] = self.ra_settings
        input_arg["enclave_sig"] = await self.sig
        input_arg["enclave_host"] = str(self.node.ip_address)
        input_arg["enclave_port"] = self.port
        input_arg["aesm_host"] = str(self.node.aesm_host)
        input_arg["aesm_port"] = self.node.aesm_port

        input_file = os.path.join(self.out_dir, "attest.yaml")
        DescriptorType.YAML.dump(input_file, input_arg)

        args = [input_file]
        out, _ = await tools.run_async_output(ATTESTER, *args)
        key_arr = eval(out)  # from string to array
        key = bytes(key_arr)  # from array to bytes

        # wait to let the enclave open the new socket
        await asyncio.sleep(0.1)

        logging.info(f"Done Remote Attestation of {self.name}. Key: {key_arr}")
        self.key = key
        self.attested = True

    async def __attest_manager(self):
        data = {
            "id": self.id,
            "name": self.name,
            "host": str(self.node.ip_address),
            "port": self.port,
            "em_port": self.node.reactive_port,
            "aesm_client_host": self.node.aesm_host,
            "aesm_client_port": self.node.aesm_port,
            "sigstruct": await self.sig,
            "config": self.ra_settings
        }
        data_file = os.path.join(self.out_dir, "attest.json")
        DescriptorType.JSON.dump(data_file, data)

        args = [
            "--config",
            get_manager().config,
            "--request",
            "attest-sgx",
            "--data",
            data_file
        ]

        out, _ = await tools.run_async_output(glob.ATTMAN_CLI, *args)
        key_arr = eval(out)  # from string to array
        key = bytes(key_arr)  # from array to bytes

        # wait to let the enclave open the new socket
        await asyncio.sleep(0.1)

        logging.info(f"Done Remote Attestation of {self.name}. Key: {key_arr}")
        self.key = key
        self.attested = True

    async def __generate_sp_keys(self):
        async with self.sp_lock:
            priv = os.path.join(glob.BUILD_DIR, "private_key.pem")
            pub = os.path.join(glob.BUILD_DIR, "public_key.pem")
            ias_cert = os.path.join(glob.BUILD_DIR, "ias_root_ca.pem")

            # check if already generated in a previous run
            if all(map(os.path.exists, [priv, pub, ias_cert])):
                return pub, priv, ias_cert

            cmd = "openssl"

            args_private = f"genrsa -f4 -out {priv} 2048".split()
            args_public = f"rsa -in {priv} -outform PEM -pubout -out {pub}".split()

            await tools.run_async_shell(cmd, *args_private)
            await tools.run_async_shell(cmd, *args_public)

            cmd = "curl"
            url = ROOT_CA_URL.split()
            await tools.run_async(cmd, *url, output_file=ias_cert)

            return pub, priv, ias_cert

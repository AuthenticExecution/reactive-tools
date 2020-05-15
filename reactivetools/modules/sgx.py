import asyncio
import logging
import os
import aiofile

from .base import Module

from ..nodes import SGXNode
from .. import tools
from .. import glob
from ..connection import Encryption

class Object():
    pass

class Error(Exception):
    pass


async def _generate_sp_keys():
    dir = tools.create_tmp_dir()

    priv = "{}/private_key.pem".format(dir)
    pub = "{}/public_key.pem".format(dir)

    cmd = "ssh-keygen"
    args_private = "-t rsa -f {} -b 2048 -N ''".format(priv).split()
    args_public = "-f {}.pub -e -m pem".format(priv).split()

    await tools.run_async_shell(cmd, *args_private)
    await tools.run_async_muted(cmd, *args_public, output_file=pub)

    return pub, priv


async def _run_ra_sp():
    # kill old ra_sp (if running)
    try:
        await tools.run_async_muted("pkill", "-f", glob.RA_SP)
    except:
        pass

    arg = await SGXModule._get_ra_sp_priv_key()

    return await tools.run_async_background(glob.RA_SP, arg)


class SGXModule(Module):
    _sp_keys_fut = asyncio.ensure_future(_generate_sp_keys())
    _ra_sp_fut = asyncio.ensure_future(_run_ra_sp())

    def __init__(self, name, node, vendor_key, ra_settings, id=None, binary=None,
                    key=None, sgxs=None, signature=None, inputs=None,
                    outputs=None, entrypoints=None):
        super().__init__(name, node)

        self.__check_init_args(node, id, binary, key, sgxs, signature, inputs, outputs, entrypoints)

        self.__deploy_fut = tools.init_future(id) # not completely true
        self.__generate_fut = tools.init_future(inputs, outputs, entrypoints)
        self.__build_fut = tools.init_future(binary)
        self.__convert_sign_fut = tools.init_future(sgxs, signature)
        self.__ra_fut = tools.init_future(key)

        self.vendor_key = vendor_key
        self.ra_settings = ra_settings
        self.id = id if id is not None else node.get_module_id()
        self.port = self.node.reactive_port + self.id
        self.output = tools.create_tmp_dir()


    # --- Properties --- #

    @property
    async def inputs(self):
        inputs, _outs, _entrys = await self.generate_code()
        return inputs


    @property
    async def outputs(self):
        _ins, outputs, _entrys = await self.generate_code()
        return outputs


    @property
    async def entrypoints(self):
        _ins, _outs, entrypoints = await self.generate_code()
        return entrypoints


    @property
    async def key(self):
        if self.__ra_fut is None:
            self.__ra_fut = asyncio.ensure_future(self.__remote_attestation())

        return await self.__ra_fut


    @property
    async def binary(self):
        if self.__build_fut is None:
            self.__build_fut = asyncio.ensure_future(self.__build())

        return await self.__build_fut


    @property
    async def sgxs(self):
        if self.__convert_sign_fut is None:
            self.__convert_sign_fut = asyncio.ensure_future(self.__convert_sign())

        sgxs, _ = await self.__convert_sign_fut

        return sgxs


    @property
    async def sig(self):
        if self.__convert_sign_fut is None:
            self.__convert_sign_fut = asyncio.ensure_future(self.__convert_sign())

        _, sig = await self.__convert_sign_fut

        return sig


    # --- Implement abstract methods --- #

    async def call(self, entry, arg=None):
        return await self.node.call(self, entry, arg)


    async def deploy(self):
        if self.__deploy_fut is None:
            self.__deploy_fut = asyncio.ensure_future(self.node.deploy(self))

        await self.__deploy_fut


    async def get_id(self):
        return self.id


    async def get_input_id(self, input):
        inputs = await self.inputs

        if input not in inputs:
            raise Error("Input not present in inputs")

        return inputs[input]


    async def get_output_id(self, output):
        outputs = await self.outputs

        if output not in outputs:
            raise Error("Output not present in outputs")

        return outputs[output]


    async def get_entry_id(self, entry):
        entrypoints = await self.entrypoints

        if entry not in entrypoints:
            raise Error("Entry not present in entrypoints")

        return entrypoints[entry]


    async def get_key(self):
        return await self.key


    @staticmethod
    def get_supported_node_type():
        return SGXNode


    @staticmethod
    def get_supported_encryption():
        return [Encryption.AES, Encryption.SPONGENT]


    # --- Static methods --- #

    @staticmethod
    async def _get_ra_sp_pub_key():
        pub, _ = await SGXModule._sp_keys_fut

        return pub


    @staticmethod
    async def _get_ra_sp_priv_key():
        _, priv = await SGXModule._sp_keys_fut

        return priv



    @staticmethod
    async def kill_ra_sp():
        process = await SGXModule._ra_sp_fut
        try:
            process.kill()
            await asyncio.sleep(0.1) # to avoid weird error messages
        except:
            pass


    # --- Others --- #

    def __check_init_args(self, node, id, binary, key, sgxs, signature, inputs, outputs, entrypoints):
        if not isinstance(node, self.get_supported_node_type()):
            clsname = lambda o: type(o).__name__
            raise Error('A {} cannot run on a {}'
                    .format(clsname(self), clsname(node)))

        # For now, either all optionals should be given or none. This might be
        # relaxed later if necessary.
        optionals = (id, binary, key, sgxs, signature, inputs, outputs, entrypoints)

        if None in optionals and any(map(lambda x: x is not None, optionals)):
            raise Error('Either all of the optional node parameters '
                        'should be given or none')


    async def generate_code(self):
        if self.__generate_fut is None:
            self.__generate_fut = asyncio.ensure_future(self.__generate_code())

        return await self.__generate_fut


    async def __generate_code(self):
        try:
            import rustsgxgen
        except:
            raise Error("rust-sgx-gen not installed! Check README.md")

        args = Object()

        args.input = self.name
        args.output = self.output
        args.moduleid = self.id
        args.key = None
        args.emport = self.node.deploy_port
        args.runner = "runner_sgx"
        args.spkey = await self._get_ra_sp_pub_key()
        args.print = None

        inputs, outputs, entrypoints = rustsgxgen.generate(args)
        logging.info("Generated code for module {}".format(self.name))

        return inputs, outputs, entrypoints


    async def __build(self):
        await self.generate_code()

        cmd = glob.BUILD_SGX_APP.format(self.output).split()
        await tools.run_async_muted(*cmd)

        binary = "{}/target/{}/{}/{}".format(self.output, glob.SGX_TARGET, glob.BUILD_MODE, self.name)

        logging.info("Built module {}".format(self.name))

        return binary


    async def __convert_sign(self):
        binary = await self.binary

        sgxs = "{}.sgxs".format(binary)
        sig = "{}.sig".format(binary)

        cmd_convert = glob.CONVERT_SGX.format(binary).split()
        cmd_sign = glob.SIGN_SGX.format(self.vendor_key, sgxs, sig).split()

        await tools.run_async_muted(*cmd_convert)
        await tools.run_async_muted(*cmd_sign)

        logging.info("Converted & signed module {}".format(self.name))

        return sgxs, sig


    async def __remote_attestation(self):
        await self.deploy()
        await self._ra_sp_fut

        args = [str(self.node.ip_address), str(self.port), self.ra_settings, await self.sig]
        key = await tools.run_async_output(glob.RA_CLIENT, *args)

        logging.info("Done Remote Attestation of {}".format(self.name))

        return key

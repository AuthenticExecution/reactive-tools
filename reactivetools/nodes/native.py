import asyncio
import aiofile
import ipaddress

from reactivenet import CommandMessageLoad

from .sgx import SGXBase
from .. import tools
from ..dumpers import *
from ..loaders import *

class NativeNode(SGXBase):
    @staticmethod
    def load(node_dict):
        name = node_dict['name']
        ip_address = ipaddress.ip_address(node_dict['ip_address'])
        reactive_port = node_dict['reactive_port']
        deploy_port = node_dict.get('deploy_port', reactive_port)

        return NativeNode(name, ip_address, reactive_port, deploy_port)


    def dump(self):
        return {
            "type": "native",
            "name": self.name,
            "ip_address": str(self.ip_address),
            "reactive_port": self.reactive_port,
            "deploy_port": self.deploy_port
        }


    async def deploy(self, module):
        if module.deployed is not None:
            return

        async with aiofile.AIOFile(await module.binary, "rb") as f:
            binary = await f.read()

        payload =   tools.pack_int32(len(binary))             + \
                    binary

        command = CommandMessageLoad(payload,
                                self.ip_address,
                                self.deploy_port)

        await self._send_reactive_command(
            command,
            log='Deploying {} on {}'.format(module.name, self.name)
            )

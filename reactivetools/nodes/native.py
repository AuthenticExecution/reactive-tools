from reactivenet import CommandMessageLoad

import aiofile

from .sgx import SGXBase
from .. import tools
from ..dumpers import *
from ..loaders import *


class NativeNode(SGXBase):
    type = "native"

    @staticmethod
    def load(node_dict):
        name = node_dict['name']
        ip_address = tools.resolve_ip(node_dict['host'])
        reactive_port = node_dict['reactive_port']
        deploy_port = node_dict.get('deploy_port') or reactive_port
        module_id = node_dict.get('module_id')

        return NativeNode(name, ip_address, reactive_port, deploy_port,
                          module_id)

    def dump(self):
        return {
            "type": self.type,
            "name": self.name,
            "host": str(self.ip_address),
            "reactive_port": self.reactive_port,
            "deploy_port": self.deploy_port,
            "module_id": self._moduleid
        }

    async def deploy(self, module):
        if module.deployed:
            return

        async with aiofile.AIOFile(await module.binary, "rb") as f:
            binary = await f.read()

        payload = tools.pack_int32(len(binary)) + \
            binary

        command = CommandMessageLoad(payload,
                                     self.ip_address,
                                     self.deploy_port)

        await self._send_reactive_command(
            command,
            log='Deploying {} on {}'.format(module.name, self.name)
        )

        module.deployed = True

import logging
import binascii
import struct

from reactivenet import ReactiveCommand, ReactiveEntrypoint, Message, \
    CommandMessage, CommandMessageLoad

import aiofile

from .base import Node
from .. import tools
from ..crypto import Encryption, hash_sha256
from ..dumpers import *
from ..loaders import *


class Error(Exception):
    pass


class TrustZoneNode(Node):
    def __init__(self, name, ip_address, reactive_port, deploy_port,
                 vendor_id, node_key, vendor_key, module_id):
        super().__init__(name, ip_address, reactive_port, deploy_port, need_lock=False)

        self.vendor_id = vendor_id
        self.node_key = node_key
        self.vendor_key = vendor_key
        self._moduleid = module_id if module_id else 1

    @staticmethod
    def load(node_dict):
        name = node_dict['name']
        ip_address = tools.resolve_ip(node_dict['host'])
        reactive_port = node_dict['reactive_port']
        deploy_port = node_dict.get('deploy_port') or reactive_port
        vendor_id = node_dict['vendor_id']
        node_key = parse_key(node_dict.get('node_key'))
        vendor_key = parse_key(node_dict.get('vendor_key'))
        module_id = node_dict.get('module_id')

        if node_key is None and vendor_key is None:
            raise Error("At least one between node key and vendor key is needed")

        # generate vendor key right away, if needed
        if vendor_key is None:
            input_hash = node_key + struct.pack('<H', vendor_id)
            vendor_key = hash_sha256(input_hash)

        return TrustZoneNode(name, ip_address, reactive_port, deploy_port,
                             vendor_id, node_key, vendor_key, module_id)

    def dump(self):
        return {
            "type": "trustzone",
            "name": self.name,
            "host": str(self.ip_address),
            "reactive_port": self.reactive_port,
            "deploy_port": self.deploy_port,
            "vendor_id": self.vendor_id,
            "node_key": dump(self.node_key) if self.node_key else None,
            "vendor_key": dump(self.vendor_key),
            "module_id": self._moduleid
        }

    async def deploy(self, module):
        assert module.node is self

        if module.deployed:
            return

        async with aiofile.AIOFile(await module.binary, "rb") as f:
            file_data = await f.read()

        temp = await module.uUID
        id_ = tools.pack_int16(module.id)
        uid = temp.to_bytes(16, 'big')
        size = struct.pack('!I', len(file_data) + len(id_) + len(uid))

        payload = size + id_ + uid + file_data

        command = CommandMessageLoad(payload,
                                     self.ip_address,
                                     self.deploy_port)

        await self._send_reactive_command(
            command,
            log=f'Deploying {module.name} on {self.name}'
        )

        module.deployed = True

    async def attest(self, module):
        assert module.node is self

        module_id = await module.get_id()

        challenge = tools.generate_key(16)

        payload = tools.pack_int16(module_id) + \
            tools.pack_int16(ReactiveEntrypoint.Attest) + \
            tools.pack_int16(len(challenge)) + \
            challenge

        command = CommandMessage(ReactiveCommand.Call,
                                 Message(payload),
                                 self.ip_address,
                                 self.reactive_port)

        res = await self._send_reactive_command(
            command,
            log=f'Attesting {module.name}'
        )

        # The result format is [tag] where the tag is the challenge's MAC
        challenge_response = res.message.payload
        expected_tag = await Encryption.AES.mac(await module.key, challenge)
        if challenge_response != expected_tag:
            logging.debug(f"Key: {await module.key}")
            logging.debug(f"Challenge: {challenge}")
            logging.debug(f"Resp: {challenge_response}")
            logging.debug(f"Expected: {expected_tag}")
            raise Error(f'Attestation of {module.name} failed')

        logging.info(f"Attestation of {module.name} succeeded")
        module.attested = True

    async def set_key(self, module, conn_id, conn_io, encryption, key):
        assert module.node is self
        assert encryption in module.get_supported_encryption()

        io_id = await conn_io.get_index(module)
        nonce = module.nonce
        module.nonce += 1

        ad = tools.pack_int8(encryption) + \
            tools.pack_int16(conn_id) + \
            tools.pack_int16(io_id) + \
            tools.pack_int16(nonce)

        cipher = await encryption.AES.encrypt(await module.get_key(), ad, key)

        payload = tools.pack_int16(module.id) + \
            tools.pack_int16(ReactiveEntrypoint.SetKey) + \
            ad + \
            cipher

        command = CommandMessage(ReactiveCommand.Call,
                                 Message(payload),
                                 self.ip_address,
                                 self.reactive_port)

        await self._send_reactive_command(
            command,
            log=f"""Setting key of connection {conn_id} ({module.name}:{conn_io.name})
                    on {self.name} to {binascii.hexlify(key).decode('ascii')}""")

    def get_module_id(self):
        id_ = self._moduleid
        self._moduleid += 1

        return id_

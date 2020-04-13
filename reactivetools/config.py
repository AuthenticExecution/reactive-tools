import json
import binascii
import ipaddress
from pathlib import Path
import os
import asyncio
import functools
import binascii
import types

import sancus.config

from .nodes import SancusNode, SGXNode, NoSGXNode
from .modules import SancusModule, SGXModule, NoSGXModule
from .connection import Connection
from . import tools


class Error(Exception):
    pass


class Config:
    def __init__(self, file_name):
        self.path = Path(file_name).resolve()
        self.nodes = []
        self.modules = []
        self.connections = []

    def get_dir(self):
        return self.path.parent

    def get_node(self, name):
        for n in self.nodes:
            if n.name == name:
                return n

        raise Error('No node with name {}'.format(name))

    def get_module(self, name):
        for m in self.modules:
            if m.name == name:
                return m

        raise Error('No module with name {}'.format(name))

    async def install_async(self):
        futures = map(Connection.establish, self.connections)
        await asyncio.gather(*futures)

    def install(self):
        asyncio.get_event_loop().run_until_complete(self.install_async())

    async def deploy_modules_ordered_async(self):
        for module in self.modules:
            await module.deploy()

    def deploy_modules_ordered(self):
        asyncio.get_event_loop().run_until_complete(
                                self.deploy_modules_ordered_async())


def load(file_name):
    with open(file_name, 'r') as f:
        contents = json.load(f)

    config = Config(file_name)
    config.nodes = _load_list(contents['nodes'], _load_node)
    config.modules = _load_list(contents['modules'],
                                lambda m: _load_module(m, config))
    config.connections = _load_list(contents['connections'],
                                    lambda c: _load_connection(c, config))
    return config


def _load_list(l, load_func=lambda e: e):
    if l is None:
        return []
    else:
        return [load_func(e) for e in l]


def _load_node(node_dict):
    return _node_load_funcs[node_dict['type']](node_dict)


def _load_sancus_node(node_dict):
    name = node_dict['name']
    vendor_id = _parse_vendor_id(node_dict['vendor_id'])
    vendor_key = _parse_vendor_key(node_dict['vendor_key'])
    ip_address = ipaddress.ip_address(node_dict['ip_address'])
    deploy_port = node_dict.get('deploy_port', 2000)
    reactive_port = node_dict.get('reactive_port', 2001)
    return SancusNode(name, vendor_id, vendor_key,
                      ip_address, deploy_port, reactive_port)


def _load_sgx_node(node_dict):
    name = node_dict['name']
    ip_address = ipaddress.ip_address(node_dict['ip_address'])
    em_port = node_dict['em_port']

    return SGXNode(name, ip_address, em_port)


def _load_nosgx_node(node_dict):
    name = node_dict['name']
    ip_address = ipaddress.ip_address(node_dict['ip_address'])
    em_port = node_dict['em_port']

    return NoSGXNode(name, ip_address, em_port)


def _load_module(mod_dict, config):
    return _module_load_funcs[mod_dict['type']](mod_dict, config)


def _load_sancus_module(mod_dict, config):
    name = mod_dict['name']
    files = _load_list(mod_dict['files'],
                       lambda f: _load_module_file(f, config))
    cflags = _load_list(mod_dict.get('cflags'))
    ldflags = _load_list(mod_dict.get('ldlags'))
    node = config.get_node(mod_dict['node'])
    binary = mod_dict.get('binary')
    id = mod_dict.get('id')
    symtab = mod_dict.get('symtab')
    key = mod_dict.get('key')
    return SancusModule(name, files, cflags, ldflags, node,
                        binary, id, symtab, key)


def _load_sgx_module(mod_dict, config):
    name = mod_dict['name']
    node = config.get_node(mod_dict['node'])

    return SGXModule(name, node)


def _load_nosgx_module(mod_dict, config):
    name = mod_dict['name']
    node = config.get_node(mod_dict['node'])

    return NoSGXModule(name, node)


def _load_connection(conn_dict, config):
    from_module = config.get_module(conn_dict['from_module'])
    from_output = conn_dict['from_output']
    to_module = config.get_module(conn_dict['to_module'])
    to_input = conn_dict['to_input']

    # Don't use dict.get() here because we don't want to call os.urandom() when
    # not strictly necessary.
    if 'key' in conn_dict:
        key = conn_dict['key']
    else:
        key = tools.generate_key(16) # TODO different lengths for different connections (e.g sancus-sgx or sgx-sgx)
         #os.urandom(sancus.config.SECURITY // 8)

    return Connection(from_module, from_output, to_module, to_input, key)


def _parse_vendor_id(id):
    if not 1 <= id <= 2**16 - 1:
        raise Error('Vendor ID out of range')

    return id


def _parse_vendor_key(key_str):
    key = binascii.unhexlify(key_str)

    if len(key) != sancus.config.SECURITY // 8:
        raise Error('Keys should be {} bit'.format(sancus.config.SECURITY))

    return key


def _load_module_file(file_name, config):
    path = Path(file_name)
    return path if path.is_absolute() else config.get_dir() / path


_node_load_funcs = {
    'sancus': _load_sancus_node,
    'sgx': _load_sgx_node,
    'nosgx': _load_nosgx_node
}


_module_load_funcs = {
    'sancus': _load_sancus_module,
    'sgx': _load_sgx_module,
    'nosgx': _load_nosgx_module
}


def dump(config, file_name):
    with open(file_name, 'w') as f:
        json.dump(_dump(config), f, indent=4)


@functools.singledispatch
def _dump(obj):
    assert False, 'No dumper for {}'.format(type(obj))


@_dump.register(Config)
def _(config):
    return {
        'nodes': _dump(config.nodes),
        'modules': _dump(config.modules),
        'connections': _dump(config.connections)
    }


@_dump.register(list)
def _(l):
    return [_dump(e) for e in l]


@_dump.register(SancusNode)
def _(node):
    return {
        "type": "sancus",
        "name": node.name,
        "ip_address": str(node.ip_address),
        "vendor_id": node.vendor_id,
        "vendor_key": _dump(node.vendor_key)
    }


@_dump.register(SancusModule)
def _(module):
    return {
        "type": "sancus",
        "name": module.name,
        "files": _dump(module.files),
        "node": module.node.name,
        "binary": _dump(module.binary),
        "symtab": _dump(module.symtab),
        "id": _dump(module.id),
        "key": _dump(module.key)
    }


@_dump.register(SGXNode)
def _(node):
    return {
        "type": "sgx",
        "name": node.name,
        "ip_address": str(node.ip_address),
        "em_port": node.deploy_port
    }


@_dump.register(SGXModule)
def _(module):
    return {
        "type": "sgx",
        "name": module.name,
        "node": module.node.name,
        "id": module.id,
        "binary": _dump(module.binary),
        "sgxs": _dump(module.sgxs),
        "signature": _dump(module.sig),
        "key": _dump(module.key),
        "inputs": module.inputs,
        "outputs": module.outputs,
        "entrypoints": module.entrypoints
    }


@_dump.register(NoSGXNode)
def _(node):
    return {
        "type": "nosgx",
        "name": node.name,
        "ip_address": str(node.ip_address),
        "em_port": node.deploy_port
    }


@_dump.register(NoSGXModule)
def _(module):
    return {
        "type": "nosgx",
        "name": module.name,
        "node": module.node.name,
        "id": module.id,
        "binary": _dump(module.binary),
        "key": _dump(module.key),
        "inputs": module.inputs,
        "outputs": module.outputs,
        "entrypoints": module.entrypoints
    }


@_dump.register(Connection)
def _(conn):
    return {
        "from_module": conn.from_module.name,
        "from_output": conn.from_output,
        "to_module": conn.to_module.name,
        "to_input": conn.to_input,
        "key": _dump(conn.key)
    }


@_dump.register(bytes)
@_dump.register(bytearray)
def _(bs):
    return binascii.hexlify(bs).decode('ascii')


@_dump.register(str)
@_dump.register(int)
def _(x):
    return x


@_dump.register(Path)
def _(path):
    return str(path)


@_dump.register(tuple)
def _(t):
    return { t[1] : t[0] }


@_dump.register(types.CoroutineType)
def _(coro):
    return _dump(asyncio.get_event_loop().run_until_complete(coro))

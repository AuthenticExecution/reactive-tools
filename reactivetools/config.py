import os
import asyncio
import logging
import time

from .modules import Module
from .nodes import Node
from .connection import Connection
from .periodic_event import PeriodicEvent
from .dumpers import *
from .loaders import *
from .rules.evaluators import *
from .descriptor import DescriptorType
from .manager import Manager, set_manager, get_manager

from .nodes import node_rules, node_funcs, node_cleanup_coros
from .modules import module_rules, module_funcs, module_cleanup_coros


class Error(Exception):
    pass


class Config:
    def __init__(self):
        self.nodes = []
        self.modules = []
        self.connections = []
        self.connections_current_id = 0
        self.events_current_id = 0
        self.output_type = None

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

    def replace_module(self, module):
        for i in range(len(self.modules)):
            m = self.modules[i]
            if m.name == module.name:
                self.modules[i] = module
                return

        raise Error('No module with name {}'.format(module.name))

    def replace_connection(self, conn):
        for i in range(len(self.connections)):
            c = self.connections[i]
            if c.id == conn.id:
                self.connections[i] = conn
                return

        raise Error('No connection with id {}'.format(conn.id))

    def get_connection_by_id(self, id_):
        for c in self.connections:
            if c.id == id_:
                return c

        raise Error('No connection with ID {}'.format(id_))

    def get_connection_by_name(self, name):
        for c in self.connections:
            if c.name == name:
                return c

        raise Error('No connection with name {}'.format(name))

    def get_periodic_event(self, name):
        for e in self.periodic_events:
            if e.name == name:
                return e

        raise Error('No periodic event with name {}'.format(name))

    async def __deploy_module(self, module):
        t1 = self.record_time()
        await module.build()
        t2 = self.record_time(t1, "Build time for {}".format(module.name))
        await module.deploy()
        self.record_time(t2, "Deploy time for {}".format(module.name))

    async def __build_module(self, module):
        t1 = self.record_time()
        await module.build()
        self.record_time(t1, "Build time for {}".format(module.name))

    async def __attest_module(self, module):
        t1 = self.record_time()
        await module.attest()
        self.record_time(t1, "Attest time for {}".format(module.name))

    async def __establish_connection(self, conn):
        t1 = self.record_time()
        await conn.establish()
        self.record_time(t1, "Establish time for {}".format(conn.name))

    async def __register_event(self, event):
        t1 = self.record_time()
        await event.register()
        self.record_time(t1, "Register time for {}".format(event.name))

    async def deploy_priority_modules(self):
        priority_modules = [
            sm for sm in self.modules if sm.priority is not None and not sm.deployed]
        priority_modules.sort(key=lambda sm: sm.priority)

        logging.debug("Priority modules: {}".format(
            [sm.name for sm in priority_modules]))
        for module in priority_modules:
            await self.__deploy_module(module)

    async def deploy_async(self, in_order, module):
        # If module is not None, deploy just this one
        if module:
            mod = self.get_module(module)
            if mod.deployed:
                raise Error('Module {} already deployed'.format(module))

            logging.info("Deploying {}".format(module))
            await self.__deploy_module(mod)
            return

        # First, deploy all modules that have a priority (in order of priority)
        await self.deploy_priority_modules()

        # If deployment in order is desired, deploy one module at a time
        if in_order:
            for m in self.modules:
                if not m.deployed:
                    await self.__deploy_module(m)
        # Otherwise, deploy all modules concurrently
        else:
            lst = self.modules

            def l_filter(x):
                return not x.deployed

            def l_map(x):
                return self.__deploy_module(x)

            futures = map(l_map, filter(l_filter, lst))
            await asyncio.gather(*futures)

    def deploy(self, in_order, module):
        asyncio.get_event_loop().run_until_complete(self.deploy_async(in_order, module))

    async def build_async(self, module):
        lst = self.modules if not module else [self.get_module(module)]

        futures = [self.__build_module(module) for module in lst]
        await asyncio.gather(*futures)

    def build(self, module):
        asyncio.get_event_loop().run_until_complete(self.build_async(module))

    async def attest_async(self, module):
        lst = self.modules if not module else [self.get_module(module)]

        to_attest = list(filter(lambda x: not x.attested, lst))

        if any(map(lambda x: not x.deployed, to_attest)):
            raise Error("One or more modules to attest are not deployed yet")

        logging.info("To attest: {}".format([x.name for x in to_attest]))

        futures = map(self.__attest_module, to_attest)
        await asyncio.gather(*futures)

    def attest(self, module):
        asyncio.get_event_loop().run_until_complete(self.attest_async(module))

    async def connect_async(self, conn):
        lst = self.connections if not conn else [
            self.get_connection_by_name(conn)]

        to_connect = list(filter(lambda x: not x.established, lst))

        if any(map(
                lambda x: (x.from_module and not x.from_module.attested) or
                not x.to_module.attested, to_connect)):
            raise Error("One or more modules to connect are not attested yet")

        logging.info("To connect: {}".format([x.name for x in to_connect]))

        futures = map(self.__establish_connection, to_connect)
        await asyncio.gather(*futures)

    def connect(self, conn):
        asyncio.get_event_loop().run_until_complete(self.connect_async(conn))

    async def register_async(self, event):
        lst = self.periodic_events if not event else [
            self.get_periodic_event(event)]

        to_register = list(filter(lambda x: not x.established, lst))

        if any(map(lambda x: not x.module.attested, to_register)):
            raise Error("One or more modules are not attested yet")

        logging.info("To register: {}".format([x.name for x in to_register]))

        futures = map(self.__register_event, to_register)
        await asyncio.gather(*futures)

    def register_event(self, event):
        asyncio.get_event_loop().run_until_complete(self.register_async(event))

    async def cleanup_async(self):
        coros = list(
            map(lambda c: c(), node_cleanup_coros + module_cleanup_coros))
        await asyncio.gather(*coros)

    def cleanup(self):
        asyncio.get_event_loop().run_until_complete(self.cleanup_async())

    async def update_async(self, module):
        if not module.deployed:
            raise Error("Module is not deployed yet.")

        t1 = self.record_time()

        # clone module
        new_module = module.clone()

        logging.info("Deploying and attesting new {}".format(module))

        await self.__deploy_module(new_module)
        await self.__attest_module(new_module)

        logging.info("Disabling old module")
        await module.old_node.disable_module(module)

        # TODO transfer state?

        # re-establish all connections that involve this module
        connections = [conn for conn in self.connections
                       if module in (conn.from_module, conn.to_module)]

        for conn in connections:
            logging.info("Re-establishing connection {} with id {}".format(conn.name, conn.id))
            new_conn = conn.clone()

            if new_conn.from_module == module:
                new_conn.from_module = new_module
            if new_conn.to_module == module:
                new_conn.to_module = new_module

            await self.__establish_connection(new_conn)
            self.replace_connection(new_conn)

        # update in conf
        new_module.old_node = new_module.node
        self.replace_module(new_module)

        logging.info("Update complete")
        self.record_time(t1, "Update time for {}".format(new_module.name))

    def update(self, module):
        asyncio.get_event_loop().run_until_complete(self.update_async(module))

    def record_time(self, previous=None, msg=None):
        if not self.measure_time:
            return None

        t = time.time()

        if not previous:
            return t

        print("{}: {:.3f}".format(msg, t - previous))

        return t


def load(file_name, manager, measure_time, output_type=None):
    config = Config()
    desc_type = DescriptorType.from_str(output_type)

    contents, input_type = DescriptorType.load_any(file_name)

    # Output file format is:
    #   - desc_type if has been provided as input, or
    #   - the same type of the input file otherwise
    config.output_type = desc_type or input_type

    config.measure_time = measure_time

    if manager:
        _load_manager(contents['manager'], config)

    config.nodes = load_list(contents['nodes'],
                             lambda n: _load_node(n, config))
    config.modules = load_list(contents['modules'],
                               lambda m: _load_module(m, config))

    config.connections_current_id = contents.get('connections_current_id') or 0
    config.events_current_id = contents.get('events_current_id') or 0

    if 'connections' in contents:
        config.connections = load_list(contents['connections'],
                                       lambda c: _load_connection(c, config))
    else:
        config.connections = []

    if 'periodic-events' in contents:
        config.periodic_events = load_list(contents['periodic-events'],
                                           lambda e: _load_periodic_event(e, config))
    else:
        config.periodic_events = []

    return config


def _load_node(node_dict, _):
    # Basic rules common to all nodes
    evaluate_rules(os.path.join("default", "node.yaml"), node_dict)
    # Specific rules for a specific node type
    evaluate_rules(os.path.join(
        "nodes", node_rules[node_dict['type']]), node_dict)

    return node_funcs[node_dict['type']](node_dict)


def _load_module(mod_dict, config):
    # Basic rules common to all nodes
    evaluate_rules(os.path.join("default", "module.yaml"), mod_dict)
    # Specific rules for a specific node type
    evaluate_rules(os.path.join(
        "modules", module_rules[mod_dict['type']]), mod_dict)

    node = config.get_node(mod_dict['node'])
    old_node = config.get_node(mod_dict.get('old_node', mod_dict['node']))
    module = module_funcs[mod_dict['type']](mod_dict, node, old_node)

    if node.__class__ not in module.get_supported_nodes():
        raise Error("Node {} ({}) does not support module {} ({})".format(
            node.name, node.__class__.__name__,
            module.name, module.__class__.__name__))

    return module


def _load_connection(conn_dict, config):
    evaluate_rules(os.path.join("default", "connection.yaml"), conn_dict)
    return Connection.load(conn_dict, config)


def _load_periodic_event(events_dict, config):
    evaluate_rules(os.path.join("default", "periodic_event.yaml"), events_dict)
    return PeriodicEvent.load(events_dict, config)


def _load_manager(man_file, config):
    if man_file is None:
        raise Error("Error while parsing manager information")

    man_dict, _ = DescriptorType.load_any(man_file)
    evaluate_rules(os.path.join("default", "manager.yaml"), man_dict)
    man = Manager.load(man_file, man_dict, config)
    set_manager(man)


def evaluate_rules(rules_file, dict_):
    rules = load_rules(rules_file)

    ok = True

    for r in rules:
        try:
            result = eval(rules[r])
        except:
            result = False

        if not result:
            logging.error("{} - Broken rule: {}".format(rules_file, r))
            ok = False

    if not ok:
        raise Error("Bad deployment descriptor")


def dump_config(config, file_name):
    config.output_type.dump(file_name, dump(config))


@dump.register(Config)
def _(config):
    man = get_manager()
    return {
        'manager': dump(man) if man is not None else None,
        'nodes': dump(config.nodes),
        'modules': dump(config.modules),
        'connections_current_id': config.connections_current_id,
        'connections': dump(config.connections),
        'events_current_id': config.events_current_id,
        'periodic-events': dump(config.periodic_events)
    }


@dump.register(Node)
def _(node):
    return node.dump()


@dump.register(Module)
def _(module):
    return module.dump()


@dump.register(Connection)
def _(conn):
    return conn.dump()


@dump.register(PeriodicEvent)
def _(event):
    return event.dump()


@dump.register(Manager)
def _(man):
    return man.dump()

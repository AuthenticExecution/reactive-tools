import argparse
import logging
import asyncio
import sys
import binascii
import os

from . import config
from . import glob


class Error(Exception):
    pass


def _setup_logging(args):
    if args.debug:
        level = logging.DEBUG
    elif args.verbose:
        level = logging.INFO
    else:
        level = logging.WARNING

    logging.basicConfig(format='%(levelname)s: %(message)s', level=level)


def _parse_args(args):
    parser = argparse.ArgumentParser()

    parser.add_argument(
        '--verbose',
        help='Verbose output',
        action='store_true')
    parser.add_argument(
        '--debug',
        help='Debug output',
        action='store_true')
    parser.add_argument(
        '--manager',
        help='Offload the task to the Attestation Manager, if possible',
        action='store_true')
    parser.add_argument(
        '--timing',
        help='Measure time between operations, for evaluation',
        action='store_true')

    subparsers = parser.add_subparsers(dest='command')
    # Workaround a Python bug. See http://bugs.python.org/issue9253#msg186387
    subparsers.required = True

    # deploy
    deploy_parser = subparsers.add_parser(
        'deploy',
        help='Deploy a reactive network')
    deploy_parser.set_defaults(command_handler=_handle_deploy)
    deploy_parser.add_argument(
        '--mode',
        help='build mode of modules. between "debug" and "release"',
        default='debug'
    )
    deploy_parser.add_argument(
        'config',
        help='Name of the configuration file describing the network')
    deploy_parser.add_argument(
        '--workspace',
        help='Root directory containing all the modules and the configuration file',
        default=".")
    deploy_parser.add_argument(
        '--result',
        help='File to write the resulting configuration to')
    deploy_parser.add_argument(
        '--deploy-in-order',
        help='Deploy modules in the order they are found in the config file',
        action='store_true')
    deploy_parser.add_argument(
        '--output',
        help='Output file type, between JSON and YAML',
        default=None)
    deploy_parser.add_argument(
        '--module',
        help='Module to deploy (if not specified, deploy all modules)',
        default=None)

    # build
    build_parser = subparsers.add_parser(
        'build',
        help='Build the executables of the SMs as declared in the input configuration file')
    build_parser.set_defaults(command_handler=_handle_build)
    build_parser.add_argument(
        '--mode',
        help='build mode of modules. between "debug" and "release"',
        default='debug'
    )
    build_parser.add_argument(
        'config',
        help='Name of the configuration file describing the network')
    build_parser.add_argument(
        '--workspace',
        help='Root directory containing all the modules and the configuration file',
        default=".")
    build_parser.add_argument(
        '--module',
        help='Module to build (if not specified, build all modules)',
        default=None)

    # attest
    attest_parser = subparsers.add_parser(
        'attest',
        help='Attest deployed modules')
    attest_parser.set_defaults(command_handler=_handle_attest)
    attest_parser.add_argument(
        'config',
        help='Specify configuration file to use')
    attest_parser.add_argument(
        '--result',
        help='File to write the resulting configuration to')
    attest_parser.add_argument(
        '--output',
        help='Output file type, between JSON and YAML',
        default=None)
    attest_parser.add_argument(
        '--module',
        help='Module to attest (if not specified, attest all modules)',
        default=None)

    # connect
    connect_parser = subparsers.add_parser(
        'connect',
        help='Connect deployed and attested modules')
    connect_parser.set_defaults(command_handler=_handle_connect)
    connect_parser.add_argument(
        'config',
        help='Specify configuration file to use')
    connect_parser.add_argument(
        '--result',
        help='File to write the resulting configuration to')
    connect_parser.add_argument(
        '--output',
        help='Output file type, between JSON and YAML',
        default=None)
    connect_parser.add_argument(
        '--connection',
        help='Connection to establish (if unspecified, establish all connections)',
        default=None)

    # register
    register_parser = subparsers.add_parser(
        'register',
        help='Register a periodic event')
    register_parser.set_defaults(command_handler=_handle_register)
    register_parser.add_argument(
        'config',
        help='Specify configuration file to use')
    register_parser.add_argument(
        '--result',
        help='File to write the resulting configuration to')
    register_parser.add_argument(
        '--output',
        help='Output file type, between JSON and YAML',
        default=None)
    register_parser.add_argument(
        '--event',
        help='Event to register (if not specified, register all events)',
        default=None)

    # call
    call_parser = subparsers.add_parser(
        'call',
        help='Call a deployed module')
    call_parser.set_defaults(command_handler=_handle_call)
    call_parser.add_argument(
        'config',
        help='Specify configuration file to use')
    call_parser.add_argument(
        '--module',
        help='Name of the module to call',
        required=True)
    call_parser.add_argument(
        '--entry',
        help='Name of the module\'s entry point to call',
        required=True)
    call_parser.add_argument(
        '--arg',
        help='Argument to pass to the entry point (hex byte array)',
        type=binascii.unhexlify,
        default=None)
    call_parser.add_argument(
        '--out',
        help='File to write the received result to')

    # output
    output_parser = subparsers.add_parser(
        'output',
        help='Trigger the output of a \"direct\" connection (between deployer and SM)')
    output_parser.set_defaults(command_handler=_handle_output)
    output_parser.add_argument(
        'config',
        help='Specify configuration file to use')
    output_parser.add_argument(
        '--connection',
        help='Connection ID or name of the connection',
        required=True)
    output_parser.add_argument(
        '--arg',
        help='Argument to pass to the output (hex byte array)',
        type=binascii.unhexlify,
        default=None)
    output_parser.add_argument(
        '--result',
        help='File to write the resulting configuration to')

    # request
    request_parser = subparsers.add_parser(
        'request',
        help='Trigger the request of a \"direct\" connection (between deployer and SM)')
    request_parser.set_defaults(command_handler=_handle_request)
    request_parser.add_argument(
        'config',
        help='Specify configuration file to use')
    request_parser.add_argument(
        '--connection',
        help='Connection ID or name of the connection',
        required=True)
    request_parser.add_argument(
        '--arg',
        help='Argument to pass to the request (hex byte array)',
        type=binascii.unhexlify,
        default=None)
    request_parser.add_argument(
        '--result',
        help='File to write the resulting configuration to')
    request_parser.add_argument(
        '--out',
        help='File to write the received result to')

    # disable
    disable_parser = subparsers.add_parser(
        'disable',
        help='Send a request to disable a module')
    disable_parser.set_defaults(command_handler=_handle_disable)
    disable_parser.add_argument(
        'config',
        help='Specify configuration file to use')
    disable_parser.add_argument(
        '--module',
        help='Name of the module to disable',
        required=True)
    disable_parser.add_argument(
        '--result',
        help='File to write the resulting configuration to')

    # update
    update_parser = subparsers.add_parser(
        'update',
        help='Update a module')
    update_parser.set_defaults(command_handler=_handle_update)
    update_parser.add_argument(
        'config',
        help='Specify configuration file to use')
    update_parser.add_argument(
        '--module',
        help='Name of the module to update',
        required=True)
    update_parser.add_argument(
        '--result',
        help='File to write the resulting configuration to')
    update_parser.add_argument(
        '--entry',
        help='Entry point of the old module to call (for state transfer)')
    update_parser.add_argument(
        '--output',
        help='Output of the old module to connect (for state transfer)')
    update_parser.add_argument(
        '--input',
        help='Input of the new module to connect (for state transfer)')

    return parser.parse_args(args)


def _handle_deploy(args):
    logging.info('Deploying %s', args.config)

    glob.set_build_mode(args.mode)

    os.chdir(args.workspace)
    conf = config.load(args.config, args.manager, args.timing, args.output)

    conf.deploy(args.deploy_in_order, args.module)

    out_file = args.result or args.config
    logging.info('Writing post-deployment configuration to %s', out_file)
    config.dump_config(conf, out_file)
    conf.cleanup()


def _handle_build(args):
    logging.info('Building %s', args.config)

    glob.set_build_mode(args.mode)

    os.chdir(args.workspace)
    conf = config.load(args.config, args.manager, args.timing)

    conf.build(args.module)
    conf.cleanup()


def _handle_attest(args):
    logging.info('Attesting modules')

    conf = config.load(args.config, args.manager, args.timing, args.output)

    conf.attest(args.module)

    out_file = args.result or args.config
    logging.info('Writing post-deployment configuration to %s', out_file)
    config.dump_config(conf, out_file)
    conf.cleanup()


def _handle_connect(args):
    logging.info('Connecting modules')

    conf = config.load(args.config, args.manager, args.timing, args.output)

    conf.connect(args.connection)

    out_file = args.result or args.config
    logging.info('Writing post-deployment configuration to %s', out_file)
    config.dump_config(conf, out_file)
    conf.cleanup()


def _handle_register(args):
    logging.info('Registering periodic events')

    conf = config.load(args.config, args.manager, args.timing, args.output)

    conf.register_event(args.event)

    out_file = args.result or args.config
    logging.info('Writing post-deployment configuration to %s', out_file)
    config.dump_config(conf, out_file)
    conf.cleanup()


def _handle_call(args):
    logging.info('Calling %s:%s', args.module, args.entry)

    conf = config.load(args.config, args.manager, args.timing)
    module = conf.get_module(args.module)

    t1 = conf.record_time()

    asyncio.get_event_loop().run_until_complete(
        module.node.call(module, args.entry, args.arg, args.out))

    conf.record_time(t1, "Call time for {}:{}".format(args.module, args.entry))

    conf.cleanup()


def _handle_output(args):
    logging.info('Triggering output of connection %s', args.connection)

    conf = config.load(args.config, args.manager, args.timing)

    if args.connection.isnumeric():
        conn = conf.get_connection_by_id(int(args.connection))
    else:
        conn = conf.get_connection_by_name(args.connection)

    if not conn.direct:
        raise Error("Connection is not direct.")

    if conn.to_input is None:
        raise Error("Not a output-input connection")

    t1 = conf.record_time()

    asyncio.get_event_loop().run_until_complete(
        conn.to_module.node.output(conn, args.arg))

    conf.record_time(t1, "Output time for {}".format(conn.name))

    conn.nonce += 1
    out_file = args.result or args.config
    config.dump_config(conf, out_file)
    conf.cleanup()


def _handle_request(args):
    logging.info('Triggering request of connection %s', args.connection)

    conf = config.load(args.config, args.manager, args.timing)

    if args.connection.isnumeric():
        conn = conf.get_connection_by_id(int(args.connection))
    else:
        conn = conf.get_connection_by_name(args.connection)

    if not conn.direct:
        raise Error("Connection is not direct.")

    if conn.to_handler is None:
        raise Error("Not a request-handler connection")

    t1 = conf.record_time()

    asyncio.get_event_loop().run_until_complete(
        conn.to_module.node.request(conn, args.arg, args.out))

    conf.record_time(t1, "Request time for {}".format(conn.name))

    conn.nonce += 2
    out_file = args.result or args.config
    config.dump_config(conf, out_file)
    conf.cleanup()


def _handle_disable(args):
    logging.info('Disabling %s', args.module)

    conf = config.load(args.config, args.manager, args.timing)
    module = conf.get_module(args.module)

    t1 = conf.record_time()

    asyncio.get_event_loop().run_until_complete(
        module.node.disable_module(module))

    conf.record_time(t1, "Disable time for {}".format(module.name))

    conf.cleanup()


def _handle_update(args):
    update_args = [args.entry, args.output, args.input]
    if any(update_args) and not all(update_args):
        raise Error("Required either none or all: [--entry, --output, --input]")

    logging.info('Updating %s', args.module)

    conf = config.load(args.config, args.manager, args.timing)
    module = conf.get_module(args.module)

    conf.update(module, args.entry, args.output, args.input)

    out_file = args.result or args.config
    logging.info('Writing post-deployment configuration to %s', out_file)
    config.dump_config(conf, out_file)
    conf.cleanup()


def main(raw_args=None):
    args = _parse_args(raw_args)
    _setup_logging(args)

    # create working directory
    try:
        os.mkdir(glob.BUILD_DIR)
    except FileExistsError:
        pass
    except:
        logging.error("Failed to create build dir")
        sys.exit(-1)

    try:
        args.command_handler(args)
    except Exception as e:
        if args.debug:
            raise

        logging.error(e)

        for task in asyncio.Task.all_tasks():
            task.cancel()

        sys.exit(-1)

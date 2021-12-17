import logging
import tempfile
import os
import asyncio
import struct
from enum import Enum
import socket
import ipaddress

from . import glob


class ProcessRunError(Exception):
    def __init__(self, cmd, args, result):
        super().__init__()
        self.cmd = cmd
        self.args = args
        self.result = result

    def __str__(self):
        return 'Command "{} {}" exited with code {}' \
            .format(self.cmd, ' '.join(self.args), self.result)


class Error(Exception):
    pass


Verbosity = Enum('Verbosity', ['Normal', 'Verbose', 'Debug'])


def get_verbosity():
    log_at = logging.getLogger().isEnabledFor

    if log_at(logging.DEBUG):
        return Verbosity.Debug
    if log_at(logging.INFO):
        return Verbosity.Verbose
    return Verbosity.Normal


def get_stderr():
    if get_verbosity() == Verbosity.Debug:
        return None

    return open(os.devnull, "wb")


def init_future(*results):
    if all(map(lambda x: x is None, results)):
        return None

    fut = asyncio.Future()
    result = results[0] if len(results) == 1 else results
    fut.set_result(result)
    return fut


async def run_async(program, *args, output_file=os.devnull, env=None):
    logging.debug(' '.join(args))

    process = await asyncio.create_subprocess_exec(program,
                                                   *args,
                                                   stdout=open(
                                                       output_file, 'wb'),
                                                   stderr=get_stderr(),
                                                   env=env)
    result = await process.wait()

    if result != 0:
        raise ProcessRunError(program, args, result)


async def run_async_background(program, *args, env=None):
    logging.debug(' '.join(args))
    process = await asyncio.create_subprocess_exec(program,
                                                   *args,
                                                   stdout=open(
                                                       os.devnull, 'wb'),
                                                   stderr=get_stderr(),
                                                   env=env)

    return process


async def run_async_output(program, *args, env=None):
    cmd = ' '.join(args)
    logging.debug(cmd)
    process = await asyncio.create_subprocess_exec(program,
                                                   *args,
                                                   stdout=asyncio.subprocess.PIPE,
                                                   stderr=asyncio.subprocess.PIPE,
                                                   env=env)
    out, err = await process.communicate()
    result = await process.wait()

    if result != 0:
        logging.error(err)
        raise ProcessRunError(program, args, result)

    return out, err


async def run_async_shell(*args, env=None):
    cmd = ' '.join(args)
    logging.debug(cmd)
    process = await asyncio.create_subprocess_shell(cmd,
                                                    stdout=open(
                                                        os.devnull, 'wb'),
                                                    stderr=get_stderr(),
                                                    env=env)
    result = await process.wait()

    if result != 0:
        raise ProcessRunError("", args, result)


def resolve_ip(host):
    # first, try to parse IP address
    try:
        return ipaddress.ip_address(host)
    except:
        pass

    # if it is not an IP address, try to resolve hostname
    try:
        ip = socket.gethostbyname(host)
        return ipaddress.ip_address(ip)
    except:
        pass

    # Otherwise, raise exception
    raise Error("Invalid host: {}".format(host))


def create_tmp(suffix='', dir_name=''):
    dir_ = os.path.join(glob.BUILD_DIR, dir_name)
    fd, path = tempfile.mkstemp(suffix=suffix, dir=dir_)
    os.close(fd)
    return path


def create_tmp_dir():
    return tempfile.mkdtemp(dir=glob.BUILD_DIR)


def generate_key(length):
    return os.urandom(length)


def pack_int8(i):
    return struct.pack('!B', i)


def unpack_int8(i):
    return struct.unpack('!B', i)[0]


def pack_int16(i):
    return struct.pack('!H', i)


def unpack_int16(i):
    return struct.unpack('!H', i)[0]


def pack_int32(i):
    return struct.pack('!I', i)


def unpack_int32(i):
    return struct.unpack('!I', i)[0]

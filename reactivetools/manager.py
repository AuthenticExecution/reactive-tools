import asyncio
import os

from . import tools
from . import glob
from .descriptor import DescriptorType

__manager = None
__is_active = False

def set_manager(man, is_active):
    global __manager
    global __is_active
    __manager = man
    __is_active = is_active

def get_manager(force=False):
    if __is_active or force:
        return __manager

    return None

class Manager:
    lock = asyncio.Lock()

    def __init__(self, file, host, port, key):
        self.config = file
        self.host = host
        self.port = port
        self.key = key
        self.sp_pubkey = None

    @staticmethod
    def load(man_file, man_dict, _):
        host = man_dict['host']
        port = man_dict['port']
        key = man_dict['key']

        return Manager(man_file, host, port, key)

    def dump(self):
        man = {
            "host": self.host,
            "port": self.port,
            "key": self.key
        }

        DescriptorType.YAML.dump(self.config, man)
        return self.config

    async def get_sp_pubkey(self):
        async with self.lock:
            if self.sp_pubkey is not None:
                return self.sp_pubkey

            args = f"--config {self.config} --request get-pub-key".split()
            out, _ = await tools.run_async_output(glob.ATTMAN_CLI, *args)

            self.sp_pubkey = os.path.join(glob.BUILD_DIR, "manager-sp_pubkey.pem")
            with open(self.sp_pubkey, "wb") as f:
                f.write(out)

            return self.sp_pubkey

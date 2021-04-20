import asyncio
import logging

class Manager:
    def __init__(self, host, port, key):
        self.host = host
        self.port = port
        self.key = key


    @staticmethod
    def load(man_dict, config):
        host = man_dict['host']
        port = man_dict['port']
        key = man_dict['key']

        return Manager(host, port, key)


    def dump(self):
        return {
            "host": self.host,
            "port": self.port,
            "key": self.key
        }

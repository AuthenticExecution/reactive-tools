import logging


class PeriodicEvent:
    def __init__(self, name, id_, module, entry, frequency, established):
        self.name = name
        self.id = id_
        self.module = module
        self.entry = entry
        self.frequency = frequency
        self.established = established

    @staticmethod
    def load(event_dict, config):
        id_ = event_dict.get('id')
        module = config.get_module(event_dict['module'])
        entry = event_dict['entry']
        frequency = event_dict['frequency']
        established = event_dict.get('established')

        if id_ is None:
            id_ = config.events_current_id  # incremental ID
            config.events_current_id += 1

        name = event_dict.get('name') or "event{}".format(id_)

        return PeriodicEvent(name, id_, module, entry, frequency, established)

    def dump(self):
        return {
            "name": self.name,
            "id": self.id,
            "module": self.module.name,
            "entry": self.entry,
            "frequency": self.frequency,
            "established": self.established
        }

    async def register(self):
        if self.established:
            return

        node = self.module.node

        await node.register_entrypoint(self.module, self.entry, self.frequency)

        logging.info('Registered %s:%s on %s every %d ms',
                     self.module.name, self.entry, node.name, self.frequency)

        self.established = True

import json
import os
from enum import IntEnum
import yaml


class Error(Exception):
    pass


class DescriptorType(IntEnum):
    JSON = 0
    YAML = 1

    @staticmethod
    def from_str(type_):
        if type_ is None:
            return None

        type_lower = type_.lower()

        if type_lower == "json":
            return DescriptorType.JSON
        if type_lower == "yaml":
            return DescriptorType.YAML

        raise Error("Bad deployment descriptor type: {}".format(type_))

    @staticmethod
    def load_any(file):
        if not os.path.exists(file):
            raise Error("Input file {} does not exist".format(file))

        try:
            return DescriptorType.JSON.load(file), DescriptorType.JSON
        except:
            try:
                return DescriptorType.YAML.load(file), DescriptorType.YAML
            except:
                raise Error(
                    "Input file {} is not a JSON, nor a YAML".format(file))

    def load(self, file):
        with open(file, 'r') as f:
            if self == DescriptorType.JSON:
                return json.load(f)

            if self == DescriptorType.YAML:
                return yaml.load(f, Loader=yaml.FullLoader)

            raise Error(
                "load not implemented for {}".format(self.name))

    def dump(self, file, data):
        with open(file, 'w') as f:
            if self == DescriptorType.JSON:
                json.dump(data, f, indent=4)

            if self == DescriptorType.YAML:
                yaml.dump(data, f)

            raise Error(
                "dump not implemented for {}".format(self.name))

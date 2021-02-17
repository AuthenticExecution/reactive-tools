from .evaluators import *

def rules(dict):
    return {
        "to_module not present":
            is_present(dict, "to_module"),
        "encryption not present":
            is_present(dict, "encryption"),

        "either direct=True or from_module + from_{output, request}":
            has_value(dict, "direct", True) != (is_present(dict, "from_module") \
            and (is_present(dict, "from_output") != is_present(dict, "from_request"))),

        "either one between to_input and to_handler":
            is_present(dict, "to_input") != is_present(dict, "to_handler"),

        "direct or from_output->to_input or from_request->to_handler":
            has_value(dict, "direct", True) or (is_present(dict, "from_output") and is_present(dict, "to_input")) \
            or (is_present(dict, "from_request") and is_present(dict, "to_handler")),

        "key present ONLY after deployment":
            (is_deploy() and not is_present(dict, "key")) or (not is_deploy() and is_present(dict, "key")),

        "nonce present ONLY after deployment":
            (is_deploy() and not is_present(dict, "nonce")) or (not is_deploy() and is_present(dict, "nonce")),

        "id present ONLY after deployment":
            (is_deploy() and not is_present(dict, "id")) or (not is_deploy() and is_present(dict, "id")),

        "name mandatory after deployment":
            is_deploy() or (not is_deploy() and is_present(dict, "name")),

        "direct mandatory after deployment":
            is_deploy() or (not is_deploy() and is_present(dict, "direct")),

        "from_module and to_module must be different":
            dict.get("from_module") != dict["to_module"],

        "only authorized keys":
            authorized_keys(dict, ["name", "from_module", "from_output",
                "from_request", "to_module", "to_input", "to_handler",
                "encryption", "key", "id", "direct", "nonce"])
    }

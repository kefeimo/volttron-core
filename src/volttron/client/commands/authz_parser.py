import argparse
import json
import re
import shutil
from typing import Callable, List

import argcomplete
import volttron.types.auth.authz_types as authz
from volttron.services.auth.auth_service import AUTH, VolttronAuthService

RPC_TIME_OUT = 10  # TODO: confirm the workflow for this config


def add_rpc_authorization(opts: argparse.Namespace):
    """
    Validates user input and calls the auth service method to add authorization to a method.

    :param opts: Contains command line pattern and connection
    :return: None
    """
    conn = opts.connection
    assert conn, "Connection not available."

    identity_list = [value.split(".") for value in opts.identity_and_method]

    print(identity_list)

    # for identity, method in opts.identity_and_method:

    # opts.identity_and_method[0]

    # agent_id = ".".join(opts.pattern[0].split(".")[:-1])
    # agent_method = opts.pattern[0].split(".")[-1]
    # if len(opts.pattern) < 2:
    #     _log.error("Missing authorizations for method. "
    #                "Should be in the format agent_id.method "
    #                "authorized_capability1 authorized_capability2 ...")
    #     return
    # added_auths = [x for x in opts.pattern[1:]]
    # try:
    #     conn.server.vip.rpc.call(AUTH, "add_rpc_authorizations", agent_id, agent_method,
    #                              added_auths).get(timeout=4)
    # except TimeoutError:
    #     _log.error(f"Adding RPC authorizations {added_auths} for {agent_id}'s "
    #                f"method {agent_method} timed out")
    # except Exception as e:
    #     _log.error(f"{e}) \nCommand format should be agent_id.method "
    #                f"authorized_capability1 authorized_capability2 ...")
    # return


def remove_agent_rpc_authorization(opts):
    """
    Removes authorizations to method in auth entry in auth file.

    :param opts: Contains command line pattern and connection
    :return: None
    """
    conn = opts.connection
    agent_id = ".".join(opts.pattern[0].split(".")[:-1])
    agent_method = opts.pattern[0].split(".")[-1]
    if len(opts.pattern) < 2:
        _log.error(
            "Missing authorizations for method. "
            "Should be in the format agent_id.method "
            "authorized_capability1 authorized_capability2 ..."
        )
        return
    removed_auths = [x for x in opts.pattern[1:]]
    try:
        conn.server.vip.rpc.call(
            AUTH,
            "delete_rpc_authorizations",
            agent_id,
            agent_method,
            removed_auths,
        ).get(timeout=4)
    except TimeoutError:
        _log.error(
            f"Adding RPC authorizations {removed_auths} for {agent_id}'s "
            f"method {agent_method} timed out"
        )
    except Exception as e:
        _log.error(
            f"{e}) \nCommand format should be agent_id.method "
            f"authorized_capability1 authorized_capability2 ..."
        )
    return


def add_authz_parser(add_parser_fn, filterable):
    """Create and populate an argparse parser for the authz command.

    First create the top level parser for authz.  Then create a subparser for
    the rpc subcommand.  Finally adds seperate arguments to the rpc subparser
    for add, remove and list commands.

    The same method as above is how the pubsub subcommand will be added.

    :param add_parser_fn: A callback that will create a new parser based upon parameters passed
    :type add_parser_fn: Callable
    :param filterable: A filter function for filtering the results of the command
    :type filterable: Callable

    EXAMPLE:
    vctl authz -h
    usage: vctl command [OPTIONS] ... authz [-h] [--debug] [-t SECS] [--address ADDR]  ...

    options:
    -h, --help            show this help message and exit
    --debug               show tracebacks for errors rather than a brief message
    -t SECS, --timeout SECS
                            timeout in seconds for remote calls (default: 60)
    --address ADDR        URL to bind for VIP connections

    authz operations:

        add                 Add rpc method authorization
        remove              Remove rpc method authorization
        list                List authorized rpc methods.
        clear               Clear authorized rpc methods.
        init                Dummy method to init auth.json
    """

    # TODO: Verify that the filterable makes sense for the authz command.

    authz_commands = add_parser_fn(
        "authz", help="Manage authorization for rpc methods and pubsub topics"
    )

    rpc_parser = authz_commands.add_subparsers(
        title="authz operations",
        metavar="<COMMAND=add|remove|list>",
        dest="store_commands",
        required=True,
        # help="Available commands are: add, remove, list",
    )

    # Create the 'add' subparser under 'rpc'
    add_authz_method = rpc_parser.add_parser("add", help="Add rpc method authorization")
    # add_authz_method.add_argument("identity_and_method", nargs="*", help="Format: 'identity.method_name'")
    # add_authz_method.set_defaults(func=handel_role_parser)

    #### Create subparser for node ('role', 'group', 'protected-topic', 'agent') under 'authz add'
    add_node_parser = add_authz_method.add_subparsers(
        title="top nodes",
        metavar="<NODE=role|group|topic|agent>",
        dest="store_commands",
        required=True,
    )

    # Add a command "role" under 'authz add'
    add_role_command = add_node_parser.add_parser("role", help="add role")
    add_role_command.add_argument("role_name", help="add role")
    add_role_command.add_argument(
        "--pubsub-capabilities", "-ps", nargs="+", help="add role --pubsub-capabilities"
    )  # TODO: confirm behavior
    add_role_command.add_argument(
        "--rpc-capabilities", "-rpc", nargs="+", help="add role --rpc-capabilities"
    )
    add_role_command.set_defaults(func=add_role)

    # Add a command "group" under 'authz add'
    add_group_command = add_node_parser.add_parser("group", help="add group")
    add_group_command.add_argument("group_name", help="add group <group_name>")
    add_group_command.add_argument(
        "vip_ids", nargs="+", help="add group <vips[s]>"
    )  # "+" means one or more inputs are required,
    add_group_command.add_argument(
        "--roles", "-rs", nargs="+", help="add group --roles <vips[s]>"
    )
    add_group_command.add_argument(
        "--pubsub-capabilities",
        "-ps",
        nargs="+",
        help="add group --pubsub-capabilities",
    )  # TODO: confirm behavior
    add_group_command.add_argument(
        "--rpc-capabilities", "-rpc", nargs="+", help="add group --rpc-capabilities"
    )
    add_group_command.set_defaults(func=print_args)

    # Add a command "protected-topics" under 'authz add'
    add_topic_command = add_node_parser.add_parser("topic", help="add topic")
    add_topic_command.add_argument(
        "topic_names", nargs="+", help="add group <topics[s]>"
    )
    add_topic_command.set_defaults(func=vctl_add_topic_demo)

    # Add a command "agent" under 'authz add'
    add_agent_command = add_node_parser.add_parser("agent", help="add agent")
    add_agent_command.add_argument(
        "vip_id", help="add agent <vip_id>"
    )  # "+" means one or more inputs are required,
    add_agent_command.add_argument(
        "--roles", "-rs", nargs="+", help="add agent --roles"
    )
    add_agent_command.add_argument(
        "--pubsub-capabilities",
        "-ps",
        nargs="+",
        help="add agent --pubsub-capabilities",
    )  # TODO: confirm behavior
    add_agent_command.add_argument(
        "--rpc-capabilities", "-rpc", nargs="+", help="add agent --rpc-capabilities"
    )
    add_agent_command.add_argument("--comments", "-c", help="add agent --comments")
    add_agent_command.set_defaults(func=print_args)

    ### REMOVE parser
    remove_authz_method = add_parser_fn(
        "remove", subparser=rpc_parser, help="Remove rpc method authorization"
    )

    #### Create subparser for node ('role', 'group', 'protected-topic', 'agent') under 'authz remove'
    remove_node_parser = remove_authz_method.add_subparsers(
        title="top nodes",
        metavar="<NODE=role|group|topic|agent>",
        dest="store_commands",
        required=True,
    )

    # Add a command "role" under 'authz remove'
    remove_role_command = remove_node_parser.add_parser("role", help="remove role")
    remove_role_command.add_argument("role_name", help="remove role")
    remove_role_command.add_argument(
        "--pubsub-capabilities", "-ps", nargs="+", help="add role --pubsub-capabilities"
    )  # TODO: confirm behavior
    remove_role_command.add_argument(
        "--rpc-capabilities", "-rpc", nargs="+", help="add role --rpc-capabilities"
    )
    remove_role_command.set_defaults(func=print_args)

    # Add a command "group" under 'authz remove'
    remove_group_command = remove_node_parser.add_parser("group", help="remove group")
    remove_group_command.add_argument("group_name", help="remove group <group_name>")
    remove_group_command.add_argument(
        "vip_ids", nargs="+", help="remove group <vips[s]>"
    )  # "+" means one or more inputs are required,
    remove_group_command.add_argument(
        "--roles", "-rs", nargs="+", help="remove group --roles <vips[s]>"
    )
    remove_group_command.add_argument(
        "--pubsub-capabilities",
        "-ps",
        nargs="+",
        help="remove group --pubsub-capabilities",
    )  # TODO: confirm behavior
    remove_group_command.add_argument(
        "--rpc-capabilities", "-rpc", nargs="+", help="remove group --rpc-capabilities"
    )
    remove_group_command.set_defaults(func=print_args)

    # Add a command "protected-topics" under 'authz remove'
    remove_topic_command = remove_node_parser.add_parser("topic", help="remove topic")
    remove_topic_command.add_argument(
        "topic_names", nargs="+", help="remove group <topics[s]>"
    )
    remove_topic_command.set_defaults(func=print_args)

    # Add a command "agent" under 'authz remove'
    remove_agent_command = remove_node_parser.add_parser("agent", help="remove agent")
    remove_agent_command.add_argument(
        "vip_id", help="add agent <vip_id>"
    )  # "+" means one or more inputs are required,
    remove_agent_command.add_argument(
        "--roles", "-rs", nargs="+", help="remove agent --roles"
    )
    remove_agent_command.add_argument(
        "--pubsub-capabilities",
        "-ps",
        nargs="+",
        help="remove agent --pubsub-capabilities",
    )  # TODO: confirm behavior
    remove_agent_command.add_argument(
        "--rpc-capabilities", "-rpc", nargs="+", help="remove agent --rpc-capabilities"
    )
    remove_agent_command.add_argument(
        "--comments", "-c", help="remove agent --comments"
    )
    remove_agent_command.set_defaults(func=print_args)

    ### LIST parser
    list_authz_method = add_parser_fn(
        "list", subparser=rpc_parser, help="List authorized rpc methods."
    )
    list_authz_method.set_defaults(func=list_dummy)
    # list_authz_method.add_argument("--capabilities", "-cap", action="store_true", help="List capabilities")
    # list_authz_method.set_defaults(func=handel_authz_list_args)

    ### CLEAR parser
    clear_authz_method = add_parser_fn(
        "clear", subparser=rpc_parser, help="Clear authorized rpc methods."
    )
    clear_authz_method.set_defaults(func=clear_dummy)
    # clear_authz_method.add_argument("--capabilities", "-cap", action="store_true", help="Clear capabilities")
    # clear_authz_method.set_defaults(func=handel_authz_clear_args)

    ### INIT parser
    init_authz_method = add_parser_fn(
        "init", subparser=rpc_parser, help="Dummy method to init auth.json"
    )
    init_authz_method.set_defaults(func=init_dummy)

    # # auto complete
    # argcomplete.autocomplete(authz_commands)
    # argcomplete.autocomplete(add_authz_method)
    # argcomplete.autocomplete(remove_authz_method)
    # argcomplete.autocomplete(list_authz_method)
    # argcomplete.autocomplete(clear_authz_method)


def vctl_add_topic_demo(opts):
    msg_1 = f"{opts.topic_names=}"
    msg_2 = f"testing topics: {get_tested_topics_demo()}"
    mapped_result = {}
    for pattern in opts.topic_names:
        for text in get_tested_topics_demo():
            if matches_wildcard(text, pattern):
                if not mapped_result.get(pattern):
                    mapped_result[pattern] = [text]
                else:
                    mapped_result[pattern].append(text)

    return msg_1 + "\n" + msg_2 + "\n" + "mapping result:" + str(mapped_result)


def print_args(opts):
    return f"{opts=}"


def get_tested_topics_demo() -> list:
    """for testing pattern `devicez/ahu*:publish`"""
    return [
        "devicez/ahu45:publish",
        "devicez/ahu64:publish",
        "devicez/ahu54:publish",
        "devicez/ahu52:publish",
        "devicez/ahugr4:publish",
        "xxxx/ahu54:publish",
        "xxxx/ahu54:publish",
        "xxxx/ahu54:publish",
        "xxx/ahu54:publish",
    ]


def matches_wildcard(text, pattern):
    """
    Check if a given text matches a pattern with wildcard '*'.

    Args:
    - text (str): The text to check against the pattern.
    - pattern (str): The pattern to match, where '*' can be any sequence of characters.

    Returns:
    - bool: True if text matches the pattern, False otherwise.

    Examples:
    >>> matches_wildcard("topic1dsdf", "topic1*")
    True
    >>> matches_wildcard("topic1ds", "topic1*")
    True
    >>> matches_wildcard("topic1", "topic1*")
    True
    >>> matches_wildcard("sdftopic", "topic1*")
    False
    >>> matches_wildcard("topicwewq1", "topic*1")
    True
    >>> matches_wildcard("topic1231", "topic*1")
    True
    """
    # Convert wildcard pattern to regex pattern
    regex_pattern = re.escape(pattern).replace("\\*", ".*")
    # Match the pattern from start to end of the string
    return re.fullmatch(regex_pattern, text) is not None


JSON_DUMMY = "/home/kefei/.volttron_modular/authz_dummy.json"
FILE_NAME = "/home/kefei/.volttron_modular/authz.json"
INIT_COPY = "/home/kefei/.volttron_modular/authz_copy.json"


def list_dummy(opts):
    with open(FILE_NAME, "r") as f:
        data = f.read()
    return data


def clear_dummy(opts):
    print(f"Your cleared the data at {JSON_DUMMY}")
    with open(JSON_DUMMY, "w") as f:
        json.dump({}, f, indent=4)


def init_dummy(opts):
    print(f"Init auth.json file at {FILE_NAME}")
    src_path = INIT_COPY
    dest_path = FILE_NAME
    try:
        # Copy the file from src_path to dest_path
        shutil.copy(src_path, dest_path)
        print(f"File copied successfully from {src_path} to {dest_path}")
    except Exception as e:
        print(f"Error occurred while copying file: {e}")


# def add_role(opts):
#     from volttron.services.control.control_service import ControlService

#     rpc_method: Callable = ControlService.add_role  # "add_role"
#     # role_name: str = opts.role_name
#     # rpc_capabilities_attr: List[str] = opts.rpc_capabilities
#     # pubsub_capabilities_attr: list[str] = opts.pubsub_capabilities

#     msg = opts.connection.call(
#         rpc_method.__name__,
#         role_name=opts.role_name,
#         rpc_capabilities_attr=opts.rpc_capabilities,
#         pubsub_capabilities_attr=opts.pubsub_capabilities,
#     )
#     # return opts
#     # print(msg)
#     return msg


### authz control
def add_role(opts):
    role_name: str = opts.role_name
    rpc_capabilities_attr: List[str] | None = opts.rpc_capabilities
    pubsub_capabilities_attr: List[str] | None = opts.pubsub_capabilities

    # authz_dict = AuthZService._load_authz(JSON_DUMMY)
    authz_dict = {}
    authz_map = authz.VolttronAuthzMap()
    authz_map.compact_dict = authz_dict
    if rpc_capabilities_attr is None:
        rpc_capabilities_attr = []
    if pubsub_capabilities_attr is None:
        pubsub_capabilities_attr = []
    rpc_caps = []
    # check rpc_cap in "id.rpc1" format
    for rpc_cap in rpc_capabilities_attr:
        if not AuthZService.is_capability_format_valid(rpc_cap):
            msg = f"Input rpc-capability '{rpc_cap}' in {rpc_capabilities_attr} does not meet the required format: {AuthZService.capability_format_requirement()}"
            return msg
        rpc_caps.append(authz.RPCCapability(rpc_cap))
    pubsub_caps = []
    # check pubsub_cap in "devicez/ahu.*:publish" format
    for pubsub_cap in pubsub_capabilities_attr:
        if ":" not in pubsub_cap:
            msg = f"Input pubsub-capability '{pubsub_cap}' in {pubsub_capabilities_attr} does not meet the required format: {AuthZService.topic_pattern_pubsub_constrain_valid_requirement()}"
            return msg
        topic_pattern = pubsub_cap.split(":")[0]
        topic_access = pubsub_cap.split(":")[-1]
        if not AuthZService.is_topic_pattern_valid(topic_pattern):
            return f"Input '<{topic_pattern=}>:<pubsub_constraint>' in {pubsub_capabilities_attr} does not meet the required format: {AuthZService.topic_pattern_requirement()}"
        if not AuthZService.is_pubsub_constrain_valid(topic_access):
            return f"Input '<topic_pattern>:<{topic_access=}>:' in {pubsub_capabilities_attr} does not meet the required format: {AuthZService.pubsub_constrain_requirement()}"
        pubsub_caps.append(
            authz.PubsubCapability(
                topic_pattern=topic_pattern, topic_access=topic_access
            )
        )

    authz_map.create_or_merge_role(
        name=role_name,
        rpc_capabilities=authz.RPCCapabilities(rpc_caps),
        pubsub_capabilities=authz.PubsubCapabilities(pubsub_caps),
    )

    # AuthZService._dump_authz(authz_map.compact_dict, JSON_DUMMY)

    # Note: rpc call in volttron-lib-auth/src/volttron/services/auth/auth_service.py
    # from volttron.services.auth.auth_service import VolttronAuthService

    rpc_method: Callable = VolttronAuthService.create_or_merge_role  # "add_role"
    # return opts.connection.server.vip.rpc.call(
    #     "platform.auth",
    #     "create_or_merge_role_1",
    #     role_name=opts.role_name,
    #     rpc_capabilities_attr=opts.rpc_capabilities,
    #     pubsub_capabilities_attr=opts.pubsub_capabilities,
    # )
    # return opts.connection.server.vip.rpc.call(
    #     "platform.auth",
    #     "create_or_merge_role_1",
    #     name=role_name,
    #     rpc_capabilities="authz.RPCCapabilities(rpc_caps)",
    #     pubsub_capabilities="authz.PubsubCapabilities(pubsub_caps)",
    # )

    # caps = authz.PubsubCapabilities()
    # caps.add_pubsub_capability(
    #     authz.PubsubCapability(
    #         topic_pattern="test_topic/subtopic", topic_access="publish"
    #     )
    # )
    # caps.add_pubsub_capability(
    #     authz.PubsubCapability(
    #         topic_pattern="test_topic_2/subtopic2", topic_access="pubsub"
    #     )
    # )

    # pubsub_capabilities = authz.PubsubCapabilities(
    #     [
    #         authz.PubsubCapability(
    #             topic_pattern="test_topic/subtopic", topic_access="publish"
    #         ),
    #         # authz.PubsubCapability(
    #         #     topic_pattern="test_topic_2/subtopic2", topic_access="pubsub"
    #         # ),
    #     ]
    # )
    # rpc_capabilities = authz.RPCCapabilities(
    #     [
    #         authz.RPCCapability(resource="vip1.method1"),
    #         # authz.RPCCapability(resource="vip2.method2"),
    #     ]
    # )

    pubsub_capabilities = authz.PubsubCapabilities(pubsub_caps)
    rpc_capabilities = authz.RPCCapabilities(rpc_caps)

    res = opts.connection.server.vip.rpc.call(
        AUTH,  # "platform.auth",
        rpc_method.__name__,  # "create_or_merge_role",
        name=role_name,
        pubsub_capabilities=pubsub_capabilities,
        rpc_capabilities=rpc_capabilities,
    ).get(RPC_TIME_OUT)

    # res = opts.connection.server.vip.rpc.call(
    #     "platform.auth",
    #     "create_or_merge_agent_authz",
    #     identity=role_name,
    #     pubsub_capabilities=pubsub_capabilities,
    #     rpc_capabilities=rpc_capabilities,
    # ).get(RPC_TIME_OUT)

    print(f"===={res}")


class AuthZService:
    @staticmethod
    def _load_authz(file_name=None):
        if not file_name:
            file_name = JSON_DUMMY
        with open(file_name, "r") as f:
            data = json.load(f)
        return data

    @staticmethod
    def _dump_authz(authz_compact_dict: dict, file_name: str = JSON_DUMMY):
        with open(file_name, "w") as f:
            json.dump(authz_compact_dict, f, indent=4)

    @staticmethod
    def _copy_file(src_path=None, dest_path=None):
        if src_path is None:
            src_path = INIT_COPY
        if dest_path is None:
            dest_path = FILE_NAME
        try:
            # Copy the file from src_path to dest_path
            shutil.copy(src_path, dest_path)
            print(f"File copied successfully from {src_path} to {dest_path}")
        except Exception as e:
            print(f"Error occurred while copying file: {e}")

    @staticmethod
    def is_capability_format_valid(cap_attr: str) -> bool:
        """
        Validates that the value follows the 'string.string' format.
        This function uses regular expression to check the pattern.
        """
        pattern = re.compile(r"^\w+\.\w+$")
        return bool(pattern.match(cap_attr))

    @staticmethod
    def capability_format_requirement() -> str:
        return "in 'str-dot-str' format. i.e., 'id1.method1'"

    @staticmethod
    def is_topic_pattern_valid(topic_patter: str) -> bool:
        """
        Check if the provided string matches the specific pattern:
        Can contain letters, '/', '.', '*', brackets, hyphens, undercore, and plus signs.

        Args:
        s (str): The string to be checked.

        Returns:
        bool: True if the string matches the format, False otherwise.

        # Examples of usage:
        test_strings = [
            "devicez/ahu.*",     # valid: follows specified characters and pattern
            "devicez/ahu[1-9]+", # valid: includes numbers and regex patterns
            "devicez/ahu-123*",  # valid: hyphen and asterisk used correctly
            "devicez/ahu+",      # valid: plus sign used correctly
            "*/auth.*",          # valid: asterisk used at the beginning and in pattern
            "invalid_string$",   # invalid: dollar sign is not in the allowed set
            "devicez/ahu(!)",    # invalid: parentheses are not allowed
            "devicez|ahu.*",     # invalid: pipe character is not allowed
            "devicez/ahu[1-9]*", # valid: correct use of brackets and asterisk
            "devicez/ahu{}",     # invalid: curly brackets are not allowed
            "hello world"        # invalid: space is not allowed
        ]
        """
        # Regex pattern to match the specified format
        pattern = r"^[a-zA-Z0-9/\.\*\[\]\-\+\_]*$"

        # Check if the string matches the pattern
        if re.match(pattern, topic_patter):
            return True
        else:
            return False

    @staticmethod
    def topic_pattern_requirement() -> str:
        example_usage = r"""
        test_strings = [
            "devicez/ahu.*",     # valid: follows specified characters and pattern
            "devicez/ahu[1-9]+", # valid: includes numbers and regex patterns
            "devicez/ahu-123*",  # valid: hyphen and asterisk used correctly
            "devicez/ahu+",      # valid: plus sign used correctly
            "*/auth.*",          # valid: asterisk used at the beginning and in pattern
            "invalid_string$",   # invalid: dollar sign is not in the allowed set
            "devicez/ahu(!)",    # invalid: parentheses are not allowed
            "devicez|ahu.*",     # invalid: pipe character is not allowed
            "devicez/ahu[1-9]*", # valid: correct use of brackets and asterisk
            "devicez/ahu{}",     # invalid: curly brackets are not allowed
            "hello world"        # invalid: space is not allowed
        ]"""
        # return f"Can contain letters, '/', '.', '*', brackets, hyphens, and plus signs. {example_usage=}"
        return bytes(
            f"Can contain letters, '/', '.', '*', brackets, hyphens, and plus signs. {example_usage=}",
            "utf-8",
        ).decode("unicode_escape")  # Manually interpreting escape sequences

    @staticmethod
    def is_pubsub_constrain_valid(pubsub_constrain: str) -> bool:
        """
        Validates pubsub_constrain
        """
        # return pubsub_constrain in ["publish", "subscribe", "pub", "sub", "pubsub"]
        return pubsub_constrain in ["publish", "subscribe", "pubsub"]

    @staticmethod
    def pubsub_constrain_requirement() -> str:
        return 'topic_access in ["publish", "subscribe", "pubsub"]'

    @classmethod
    def is_topic_pattern_pubsub_constrain_valid(cls, input_string: str) -> bool:
        """
        Checks if the input string follows the format '<topic_pattern>:<pubsub_constraint>'

        Args:
        input_string (str): The input string to validate.

        Returns:
        bool: True if the input string is valid, False otherwise.
        """
        # Split the input string by the colon
        parts = input_string.split(":")

        # Ensure there are exactly two parts
        if len(parts) != 2:
            return False

        # Validate each part
        topic_pattern, pubsub_constrain = parts
        return cls.is_topic_pattern_valid(
            topic_pattern
        ) and cls.is_pubsub_constrain_valid(pubsub_constrain)

    @staticmethod
    def topic_pattern_pubsub_constrain_valid_requirement() -> str:
        example_usage = r"""
        [
            "devicez/ahu.*:publish",         # valid
            "*/auth.*:pubsub",               # valid
            "devicez/ahu(!):publish",        # invalid: topic pattern invalid
            "devicez|ahu.*:fly",             # invalid: pubsub constraint invalid
            "devicez/ahu[1-9]*:subscribe"    # valid
        ]"""
        print(
            "The input string needs to follow the format '<topic_pattern>:<pubsub_constraint>'."
        )
        # print(example_usage)
        # return f"The input string needs to follow the format '<topic_pattern>:<pubsub_constraint>'. {example_usage=}"
        return bytes(
            f"The input string needs to follow the format '<topic_pattern>:<pubsub_constraint>'. {example_usage=}",
            "utf-8",
        ).decode("unicode_escape")  # Manually interpreting escape sequences

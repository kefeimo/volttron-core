import argparse
import re

import argcomplete
import volttron.types.auth.authz_types as authz


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
    add_role_command.set_defaults(func=print_args)

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
    # list_authz_method.add_argument("--capabilities", "-cap", action="store_true", help="List capabilities")
    # list_authz_method.set_defaults(func=handel_authz_list_args)

    ### CLEAR parser
    clear_authz_method = add_parser_fn(
        "clear", subparser=rpc_parser, help="Clear authorized rpc methods."
    )
    # clear_authz_method.add_argument("--capabilities", "-cap", action="store_true", help="Clear capabilities")
    # clear_authz_method.set_defaults(func=handel_authz_clear_args)

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

import argparse
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
        _log.error("Missing authorizations for method. "
                   "Should be in the format agent_id.method "
                   "authorized_capability1 authorized_capability2 ...")
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
        _log.error(f"Adding RPC authorizations {removed_auths} for {agent_id}'s "
                   f"method {agent_method} timed out")
    except Exception as e:
        _log.error(f"{e}) \nCommand format should be agent_id.method "
                   f"authorized_capability1 authorized_capability2 ...")
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

    authz_commands = add_parser_fn("authz",
                                   help="Manage authorization for rpc methods and pubsub topics")

    rpc_parser = authz_commands.add_subparsers(title="authz operations", metavar="", dest="store_commands")

    # Create the 'add' subparser under 'rpc'
    add_authz_method = rpc_parser.add_parser("add", help="Add rpc method authorization")
    # add_authz_method.add_argument("identity_and_method", nargs="*", help="Format: 'identity.method_name'")
    # add_authz_method.set_defaults(func=handel_role_parser)
    
    #### Create subparser for node ('role', 'group', 'protected-topic', 'agent') under 'authz add'
    add_node_parser = add_authz_method.add_subparsers(title="top nodes", metavar="", dest="store_commands")

    # Add a command "role" under 'authz add'
    add_role_command  = add_node_parser.add_parser("role", help="add role")
    add_role_command.add_argument("--pubsub-capabilities", "-pscaps",nargs="*", help="add role pubsub-capabilities")  # TODO: confirm behavior
    add_role_command.add_argument("--rpc-capabilities", "-rpccap", nargs="*", help="add role rpc-capabilities")
    
    # Add a command "group" under 'authz add'
    add_group_command  = add_node_parser.add_parser("group", help="add group")
    add_group_command.add_argument("--pubsub-capabilities", "-pscaps",nargs="*", help="add group pubsub-capabilities")  # TODO: confirm behavior
    add_group_command.add_argument("--rpc-capabilities", "-rpccap", nargs="*", help="add group rpc-capabilities")
    
    
   
    ### REMOVE parser
    remove_authz_method = add_parser_fn(
        "remove",
        subparser=rpc_parser,
        help="Remove rpc method authorization")
    
    #### Create subparser for node ('role', 'group', 'protected-topic', 'agent') under 'authz remove'
    remove_node_parser = remove_authz_method.add_subparsers(title="top nodes", metavar="", dest="store_commands")

    # Add a command "role" under 'authz remove'
    remove_role_command  = remove_node_parser.add_parser("role", help="add role")
    remove_role_command.add_argument("--pubsub-capabilities", "-pscaps",nargs="*", help="remove role pubsub-capabilities")  # TODO: confirm behavior
    remove_role_command.add_argument("--rpc-capabilities", "-rpccap", nargs="*", help="remove role rpc-capabilities")
    
    # Add a command "group" under 'authz remove'
    remove_group_command  = remove_node_parser.add_parser("group", help="add group")
    remove_group_command.add_argument("--pubsub-capabilities", "-pscaps",nargs="*", help="remove group pubsub-capabilities")  # TODO: confirm behavior
    remove_group_command.add_argument("--rpc-capabilities", "-rpccap", nargs="*", help="remove group rpc-capabilities")

    ### LIST parser
    list_authz_method = add_parser_fn("list",
                                      subparser=rpc_parser,
                                      help="List authorized rpc methods.")
    # list_authz_method.add_argument("--capabilities", "-cap", action="store_true", help="List capabilities")
    # list_authz_method.set_defaults(func=handel_authz_list_args)
    
    ### CLEAR parser
    clear_authz_method = add_parser_fn("clear",
                                      subparser=rpc_parser,
                                      help="Clear authorized rpc methods.")
    # clear_authz_method.add_argument("--capabilities", "-cap", action="store_true", help="Clear capabilities")
    # clear_authz_method.set_defaults(func=handel_authz_clear_args)
    
    
    
   
    # # auto complete
    # argcomplete.autocomplete(authz_commands)
    # argcomplete.autocomplete(add_authz_method)
    # argcomplete.autocomplete(remove_authz_method)
    # argcomplete.autocomplete(list_authz_method)
    # argcomplete.autocomplete(clear_authz_method)
    
def handel_role_parser(opts):
    return f"handel_role_parser, {opts=}"


def dummy_func(opts):
    return "dummy funct"

def handel_authz_add_args(args):
    """Function to handle `vctl authz add ` argument."""
    if args.capabilities:
        return add_rpc_capabilities(args.capabilities)
    else:
        print("No capabilities provided.")
        
def handel_authz_remove_args(args):
    """Function to handle `vctl authz remove ` argument."""
    if args.capabilities:
        return remove_rpc_capabilities(args.capabilities)
    else:
        print("No capabilities provided.")

def handel_authz_list_args(args):
    """Function to handle `vctl authz list ` argument."""
    if args.capabilities:
        return print_authz_list_capabilities()
    else:
        pass
    
def handel_authz_clear_args(args):
    """Function to handle `vctl authz clear ` argument."""
    if args.capabilities:
        return clear_rpc_capabilities()
    else:
        pass
        

### Place-holder for Auth Servers
# add_rpc_capabilities logic (w persistent capabilities_obj)
import ast

# FILE_PATH = "/home/kefei/project/volttron-modular/capbilities_rpc_dict_str.txt"
FILE_PATH = "capbilities_rpc_dict_str.txt"

def parse_input_to_list(user_input):
    """
    Parses a string containing elements separated by common delimiters
    (spaces, commas, semicolons) into a list of strings.

    Parameters:
    - user_input (str): A string input from the user.

    Returns:
    - List[str]: A list of strings extracted from the input.

    Examples:
    >>> parse_input_to_list("apple banana mango")
    ['apple', 'banana', 'mango']

    >>> parse_input_to_list("red, green, blue")
    ['red', 'green', 'blue']

    >>> parse_input_to_list("first; second; third")
    ['first', 'second', 'third']

    >>> parse_input_to_list("python; javascript, ruby c++")
    ['python', 'javascript', 'ruby', 'c++']

    >>> parse_input_to_list("  data science, machine learning; artificial intelligence   deep learning ")
    ['data', 'science', 'machine', 'learning', 'artificial', 'intelligence', 'deep', 'learning']

    >>> parse_input_to_list(",; , ;")
    []

    """
    import re
    # Split on any sequence of space, comma, or semicolon
    tokens = re.split(r'[ ,;]+', user_input.strip())
    # Filter out empty strings if any remain after splitting
    return [token for token in tokens if token]
    

def load_file(file_path: str):
    """
    Reads the content of a local file and returns it as a string.
    If the file does not exist, creates an empty file at the specified path.

    Args:
    file_path (str): The path to the file to be read.

    Returns:
    str: The content of the file, or an empty string if the file was just created.
    """
    try:
        with open(file_path, 'r') as file:
            return file.read()
    except FileNotFoundError:
        with open(file_path, 'w') as file:  # Create an empty file if not found
            pass
        return ""  # Return an empty string as the file is empty
    except Exception as e:
        return str(e)

def save_to_file(content: str, file_path: str):
    """
    Writes a given string to a specified local file.

    Args:
    content (str): The string to be written to the file.
    file_path (str): The path to the file where the content will be saved.

    Returns:
    str: Confirmation message indicating success or failure.
    """
    try:
        with open(file_path, 'w') as file:
            file.write(content)
        return "Content saved successfully."
    except Exception as e:
        return str(e)
    
def unstructure_rev(unstructured: str) -> authz.RPCCapabilities:
    python_obj: List[str] | str = ast.literal_eval(unstructured)
    # if type(python_obj) is not list:
    #     capabilities_to_add = [python_obj] 
    caps = authz.RPCCapabilities()
    for cap_arg in python_obj:
        caps.add_rpc_capability(authz.RPCCapability(cap_arg))
    return caps
    
def clear_rpc_capabilities():
    """
    Helper function to clear all capabilities in the RPCCapabilities instance.
    """    
    # persist obj: save
    save_to_file(content="", file_path=FILE_PATH) 
    return "Cleared capabilities."

def add_rpc_capabilities(capabilities_to_add_arg: str) -> authz.RPCCapabilities:
    """
    Helper function to add capabilities to (existing) RPCCapabilities instance, 
    Take str as input, in the format of (after eval) List[str], e.g., id1.rpc1"""
    # persist obj: load
    capabilities_arg: str = load_file(FILE_PATH)
    
    if not capabilities_arg:
        capabilities_obj = authz.RPCCapabilities()
    else:
        capabilities_obj = unstructure_rev(capabilities_arg)
    # print(f"{capabilities_to_add_arg}")
    # capabilities_to_add_arg_obj = parse_input_to_list(capabilities_to_add_arg)
    capabilities_to_add_arg_obj = capabilities_to_add_arg
    # f"========={type(capabilities_to_add_arg_obj)=}"
    if type(capabilities_to_add_arg_obj) is not list:
        capabilities_to_add_arg_obj = [capabilities_to_add_arg_obj] 
    # TODO: add type check here. Currrently the type is not well defined.
    for cap_arg in capabilities_to_add_arg_obj:
        capabilities_obj.add_rpc_capability(authz.RPCCapability(cap_arg))
    
    # persist obj: save
    save_to_file(content=str(capabilities_obj._rpc_dict), file_path=FILE_PATH) 
    
    return f"Updated Capabilities to: {capabilities_obj._rpc_dict}."

# clear_rpc_capabilities()
# add_str = "[]"
# print(f"{add_rpc_capabilities(add_str)=}")
# add_str = "['id.rpc1', 'id2.rpc2']"
# print(f"{add_rpc_capabilities(add_str)=}")
# add_str = "['id3.rpc3', 'id4.rpc4']"
# print(f"{add_rpc_capabilities(add_str)=}")

# Remove logic
def remove_rpc_capabilities(capabilities_to_remove_arg: str) -> authz.RPCCapabilities:
    """
    Helper function to remove capabilities to (existing) RPCCapabilities instance, 
    Take str as input, in the format of (after eval) List[str], e.g., `["id1.rpc1", "id2.rpc2"]`. """
    # persist obj: load
    capabilities_arg: str = load_file(FILE_PATH)
    
    if not capabilities_arg:
        capabilities_obj = authz.RPCCapabilities()
    else:
        capabilities_obj = unstructure_rev(capabilities_arg)
    # capabilities_to_remove_arg_obj = ast.literal_eval(capabilities_to_remove_arg)
    capabilities_to_remove_arg_obj = capabilities_to_remove_arg
    # f"========={type(capabilities_to_add_arg_obj)=}"
    if type(capabilities_to_remove_arg) is not list:
        capabilities_to_remove_arg = [capabilities_to_remove_arg] 
    # TODO: add type check here. Currrently the type is not well defined.
    for cap_arg in capabilities_to_remove_arg_obj:
        capabilities_obj.remove_rpc_capability(authz.RPCCapability(cap_arg))
    # persist obj: save
    # print(f"========={capabilities_obj=}")
    save_to_file(content=str(capabilities_obj._rpc_dict), file_path=FILE_PATH) 
    
    return f"Updated Capabilities to: {capabilities_obj._rpc_dict}."

# clear_rpc_capabilities()
# add_str = "[]"
# print(f"{add_rpc_capabilities(add_str)=}")
# add_str = "['id.rpc1', 'id2.rpc2', 'id3.rpc3', 'id4.rpc4']"
# print(f"{add_rpc_capabilities(add_str)=}")
# remove_str = "['id3.rpc3']"
# print(f"{remove_rpc_capabilities(remove_str)=}")

# list logic
def list_rpc_capabilities() -> authz.RPCCapabilities:
    """
    Helper function to list the capabilities. (from the persisted file)"""
    # persist obj: load
    capabilities_arg: str = load_file(FILE_PATH)
    
    if not capabilities_arg:
        capabilities_obj = authz.RPCCapabilities()
    else:
        capabilities_obj = unstructure_rev(capabilities_arg)
    
    return capabilities_obj


# clear_rpc_capabilities()
# print(f"{list_rpc_capabilities()=}")
# add_str = "['id.rpc1', 'id2.rpc2', 'id3.rpc3', 'id4.rpc4']"
# print(f"{add_rpc_capabilities(add_str)=}")
# print(f"{list_rpc_capabilities()=}")





# Function to print the table
def print_authz_list_capabilities():
    """
    Print out the dict-like capabilities info into a table.
    EXAMPLE:
    resource        |       para_constraints
    ------------------------------
    id2.method2     |       {}              
    id3.method3     |       {}   
    
    """
    # get the cap instance
    vctl_authz_list_cap = list_rpc_capabilities()
    if not vctl_authz_list_cap._rpc_dict:
        return "There is no capabilites defined."
    # Define a list of dictionaries, simulating DataFrame rows
    resources = [res for res in vctl_authz_list_cap._rpc_dict.keys()]
    para_constraints = [para_con for para_con in vctl_authz_list_cap._rpc_dict.values()]
    data = [{'resource': res, 'para_constraints': con} for res, con in zip(resources, para_constraints)]
    # Headers are the keys from the first dictionary (assuming all dicts have the same keys)
    headers = data[0].keys() if data else []
    
    # Find the maximum width for each column
    column_widths = {}
    for header in headers:
        column_widths[header] = max(len(str(row[header])) for row in data)
        column_widths[header] = max(column_widths[header], len(header))
    
    # Create the header row
    header_row = "\t|\t".join(header.ljust(column_widths[header]) for header in headers)
    print(header_row)
    print('-' * len(header_row))
    
    # Print the data rows
    for row in data:
        print("\t|\t".join(str(row[header]).ljust(column_widths[header]) for header in headers))

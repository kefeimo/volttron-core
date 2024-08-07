# -*- coding: utf-8 -*- {{{
# ===----------------------------------------------------------------------===
#
#                 Installable Component of Eclipse VOLTTRON
#
# ===----------------------------------------------------------------------===
#
# Copyright 2022 Battelle Memorial Institute
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy
# of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
# ===----------------------------------------------------------------------===
# }}}

import logging
import glob
import os
import os.path
import errno
from csv import DictReader
from io import StringIO
from deprecated import deprecated
import gevent

from gevent.lock import Semaphore

from volttron.types import ServiceInterface
from volttron.utils import (
    parse_json_config,
    get_aware_utc_now,
    format_timestamp,
)
from volttron.utils import jsonapi

from volttron.utils.persistance import PersistentDict

from volttron.utils.jsonrpc import RemoteError, MethodNotFound
from volttron.utils.storeutils import check_for_recursion, strip_config_name, store_ext
from volttron.client.vip.agent import Agent, Core, RPC, Unreachable, VIPError
from volttron.services.auth.auth_service import AuthFile, AuthEntry

_log = logging.getLogger(__name__)

UPDATE_TIMEOUT = 30.0


def process_store(identity, store):
    """Parses raw store data and returns contents.
    Called at startup to initialize the parsed version of the store."""
    results = {}
    name_map = {}
    sync_store = False
    for config_name, config_data in store.items():
        config_type = config_data["type"]
        config_string = config_data["data"]
        try:
            processed_config = process_raw_config(config_string, config_type)
            if check_for_recursion(config_name, processed_config, results):
                raise ValueError("Recursive configuration references")
            results[config_name] = processed_config
        except ValueError as e:
            _log.error("Error processing Agent {} config {}: {}".format(identity, config_name, str(e)))
            sync_store = True
            del store[config_name]

        if config_name.lower() in name_map:
            _log.error("Conflicting names in store, dropping {}".format(config_name))
            sync_store = True
            del store[config_name]

        else:
            name_map[config_name.lower()] = config_name

    if sync_store:
        _log.warning("Removing invalid configurations for Agent {}".format(identity))
        store.sync()

    return results, name_map


def process_raw_config(config_string, config_type="raw"):
    """Parses raw config string into python objects"""
    if config_type == "raw":
        return config_string
    elif config_type == "json":
        config = parse_json_config(config_string)
        if not isinstance(config, (list, dict)):
            raise ValueError("Configuration must be a list or object.")
        return config
    elif config_type == "csv":
        f = StringIO(config_string)
        return [x for x in DictReader(f)]

    raise ValueError("Unsupported configuration type.")


class ConfigStoreService(ServiceInterface):

    def __init__(self, **kwargs):
        kwargs["enable_store"] = False
        super(ConfigStoreService, self).__init__(**kwargs)

        # This agent is started before the router so we need
        # to keep it from blocking.
        self.core.delay_running_event_set = False

        self.store = {}
        self.store_path = os.path.join(os.environ["VOLTTRON_HOME"], "configuration_store")
        entry = AuthEntry(
            credentials=self.core.publickey,
            user_id=self.core.identity,
            capabilities="sync_agent_config",
            comments="Automatically added by config store service"
        )
        AuthFile().add(entry, overwrite=True)


    @Core.receiver("onsetup")
    def _setup(self, sender, **kwargs):
        _log.info("Initializing configuration store service.")

        try:
            # explicitly provide access to others. Needed for secure mode.
            # Agents needs access to its own store file in this dir
            os.makedirs(self.store_path)
            os.chmod(self.store_path, 0o755)
        except OSError as e:
            if e.errno != errno.EEXIST:
                _log.critical("Failed to create configuration store directory: " + str(e))
                raise
            else:
                _log.debug("Configuration directory already exists.")

        config_store_iter = glob.iglob(os.path.join(self.store_path, "*" + store_ext))

        for store_path in config_store_iter:
            root, ext = os.path.splitext(store_path)
            agent_identity = os.path.basename(root)
            _log.debug("Processing store for agent {}".format(agent_identity))
            store = PersistentDict(filename=store_path, flag="c", format="json")
            parsed_configs, name_map = process_store(agent_identity, store)
            self.store[agent_identity] = {
                "configs": parsed_configs,
                "store": store,
                "name_map": name_map,
                "lock": Semaphore(),
            }

    @RPC.export
    @RPC.allow("edit_config_store")
    @deprecated(reason="Use set_config")
    def manage_store(self, identity, config_name, raw_contents, config_type="raw", trigger_callback=True,
                     send_update=True):
        """
        This method is deprecated and will be removed in VOLTTRON 10. Please use set_config instead
        """
        contents = process_raw_config(raw_contents, config_type)
        self._add_config_to_store(identity, config_name, raw_contents, contents, config_type,
                                  trigger_callback=trigger_callback, send_update=send_update)

    @RPC.export
    @RPC.allow('edit_config_store')
    def set_config(self, identity, config_name, raw_contents, config_type="raw", trigger_callback=True,
                   send_update=True):
        contents = process_raw_config(raw_contents, config_type)
        self._add_config_to_store(identity, config_name, raw_contents, contents, config_type,
                                  trigger_callback=trigger_callback, send_update=send_update)

    @RPC.export
    @RPC.allow('edit_config_store')
    @deprecated(reason="Use delete_config")
    def manage_delete_config(self, identity, config_name, trigger_callback=True, send_update=True):
        """
        This method is deprecated and will be removed in VOLTTRON 10. Please use delete_config instead
        """
        self.delete(identity, config_name, trigger_callback=trigger_callback, send_update=send_update)

    @RPC.export
    @RPC.allow('edit_config_store')
    def delete_config(self, identity, config_name, trigger_callback=True, send_update=True):
        self.delete(identity, config_name, trigger_callback=trigger_callback, send_update=send_update)

    @RPC.export
    @RPC.allow('edit_config_store')
    @deprecated(reason="Use delete_store")
    def manage_delete_store(self, identity):
        """
        This method is deprecated and will be removed in VOLTTRON 10. Please use delete_store instead
        """
        self.delete_store(identity)

    @RPC.export
    @RPC.allow('edit_config_store')
    def delete_store(self, identity):
        agent_store = self.store.get(identity)
        if agent_store is None:
            return

        agent_configs = agent_store["configs"]
        agent_disk_store = agent_store["store"]
        agent_store_lock = agent_store["lock"]
        agent_name_map = agent_store["name_map"]

        agent_configs.clear()
        agent_disk_store.clear()
        agent_name_map.clear()

        # Sync will delete the file if the store is empty.
        agent_disk_store.async_sync()

        if identity in self.vip.peerlist.peers_list:
            with agent_store_lock:
                try:
                    self.vip.rpc.call(identity,
                                      "config.update",
                                      "DELETE_ALL",
                                      None,
                                      trigger_callback=True).get(timeout=UPDATE_TIMEOUT)
                except Unreachable:
                    _log.debug("Agent {} not currently running. Configuration update not sent.".format(identity))
                except RemoteError as e:
                    _log.error("Agent {} failure when all configurations: {}".format(identity, e))
                except MethodNotFound as e:
                    _log.error("Agent {} failure when deleting configuration store: {}".format(identity, e))

        # If the store is still empty (nothing jumped in and added to it while
        # we were informing the agent) then remove it from the global store.
        if not agent_disk_store:
            self.store.pop(identity, None)

    @RPC.export
    @deprecated(reason="Use list_configs")
    def manage_list_configs(self, identity):
        """
        This method is deprecated and will be removed in VOLTTRON 10. Use list_configs instead
        """
        return self.list_configs(identity)

    @RPC.export
    def list_configs(self, identity):
        result = list(self.store.get(identity, {}).get("store", {}).keys())
        result.sort()
        return result

    @RPC.export
    @deprecated(reason="Use list_stores")
    def manage_list_stores(self):
        """
        This method is deprecated and will be removed in VOLTTRON 10. Use list_stores instead
        """
        return self.list_stores()

    @RPC.export
    def list_stores(self):
        result = list(self.store.keys())
        result.sort()
        return result

    @RPC.export
    @deprecated(reason="Use get_config")
    def manage_get(self, identity, config_name, raw=True):
        """
        This method is deprecated and will be removed in VOLTTRON 10. Use get_config instead
        """
        return self.get_config(identity, config_name, raw)

    @RPC.export
    def get_config(self, identity, config_name, raw=True):
        agent_store = self.store.get(identity)
        if agent_store is None:
            raise KeyError('No configuration file "{}" for VIP IDENTITY {}'.format(config_name, identity))

        agent_configs = agent_store["configs"]
        agent_disk_store = agent_store["store"]
        agent_name_map = agent_store["name_map"]

        config_name = strip_config_name(config_name)
        config_name_lower = config_name.lower()

        if config_name_lower not in agent_name_map:
            raise KeyError('No configuration file "{}" for VIP IDENTITY {}'.format(config_name, identity))

        real_config_name = agent_name_map[config_name_lower]

        if raw:
            return agent_disk_store[real_config_name]["data"]

        return agent_configs[real_config_name]

    @RPC.export
    @deprecated(reason="Use get_metadata")
    def manage_get_metadata(self, identity, config_name):
        """
        This method is deprecated and will be removed in VOLTTRON 10. Please use get_metadata instead
        """
        return self.get_metadata(identity, config_name)

    @RPC.export
    def get_metadata(self, identity, config_name):
        agent_store = self.store.get(identity)
        if agent_store is None:
            raise KeyError('No configuration file "{}" for VIP IDENTITY {}'.format(config_name, identity))

        agent_disk_store = agent_store["store"]
        agent_name_map = agent_store["name_map"]

        config_name = strip_config_name(config_name)
        config_name_lower = config_name.lower()

        if config_name_lower not in agent_name_map:
            raise KeyError('No configuration file "{}" for VIP IDENTITY {}'.format(config_name, identity))

        real_config_name = agent_name_map[config_name_lower]

        real_config = agent_disk_store[real_config_name]

        # Set modified to none if we predate the modified flag.
        if real_config.get("modified") is None:
            real_config["modified"] = None

        return real_config

    @RPC.allow('edit_config_store')
    @RPC.export
    def initialize_configs(self, identity):
        """
        Called by an Agent at startup to trigger initial configuration state
        push.
        """

        # We need to create store and lock if it doesn't exist in case someone
        # tries to add a configuration while we are sending the initial state.
        agent_store = self.store.get(identity)

        if agent_store is None:
            # Initialize a new store.
            store_path = os.path.join(self.store_path, identity + store_ext)
            store = PersistentDict(filename=store_path, flag="c", format="json")
            agent_store = {
                "configs": {},
                "store": store,
                "name_map": {},
                "lock": Semaphore(),
            }
            self.store[identity] = agent_store

        agent_configs = agent_store["configs"]
        agent_disk_store = agent_store["store"]
        agent_store_lock = agent_store["lock"]
        if identity in self.vip.peerlist.peers_list:
            with agent_store_lock:
                try:
                    self.vip.rpc.call(identity, "config.initial_update",
                                      agent_configs).get(timeout=UPDATE_TIMEOUT)
                except Unreachable:
                    _log.debug("Agent {} not currently running. Configuration update not sent.".format(identity))
                except RemoteError as e:
                    _log.error("Agent {} failure when performing initial update: {}".format(identity, e))
                except MethodNotFound as e:
                    _log.error("Agent {} failure when performing initial update: {}".format(identity, e))
                except VIPError as e:
                    _log.error("VIP Error sending initial agent configuration: {}".format(e))

        # If the store is empty (and nothing jumped in and added to it while we
        # were informing the agent) then remove it from the global store.
        if not agent_disk_store:
            self.store.pop(identity, None)

    # Helper method to allow the local services to delete configs before message
    # bus in online.
    def delete(self, identity, config_name, trigger_callback=False, send_update=True):
        agent_store = self.store.get(identity)
        if agent_store is None:
            raise KeyError('No configuration file "{}" for VIP IDENTITY {}'.format(config_name, identity))

        agent_configs = agent_store["configs"]
        agent_disk_store = agent_store["store"]
        agent_store_lock = agent_store["lock"]
        agent_name_map = agent_store["name_map"]

        config_name = strip_config_name(config_name)
        config_name_lower = config_name.lower()

        if config_name_lower not in agent_name_map:
            raise KeyError('No configuration file "{}" for VIP IDENTITY {}'.format(config_name, identity))

        real_config_name = agent_name_map[config_name_lower]

        agent_configs.pop(real_config_name)
        agent_disk_store.pop(real_config_name)
        agent_name_map.pop(config_name_lower)

        # Sync will delete the file if the store is empty.
        agent_disk_store.async_sync()

        if send_update and identity in self.vip.peerlist.peers_list:
            with agent_store_lock:
                try:
                    self.vip.rpc.call(
                        identity,
                        "config.update",
                        "DELETE",
                        config_name,
                        trigger_callback=trigger_callback,
                    ).get(timeout=UPDATE_TIMEOUT)
                except Unreachable:
                    _log.debug("Agent {} not currently running. Configuration update not sent.".format(identity))
                except RemoteError as e:
                    _log.error("Agent {} failure when deleting configuration {}: {}".format(identity, config_name, e))
                except MethodNotFound as e:
                    _log.error(
                        "Agent {} failure when adding/updating configuration {}: {}".format(identity, config_name, e))

        # If the store is empty (and nothing jumped in and added to it while we
        # were informing the agent) then remove it from the global store.
        if not agent_disk_store:
            self.store.pop(identity, None)

    # Helper method to allow the local services to store configs before message
    # bus is online.
    def store_config(self, identity, config_name, contents, trigger_callback=False, send_update=True):
        config_type = None
        raw_data = None
        if isinstance(contents, (dict, list)):
            config_type = "json"
            raw_data = jsonapi.dumps(contents)
        elif isinstance(contents, str):
            config_type = "raw"
            raw_data = contents
        else:
            raise ValueError("Unsupported configuration content type: {}".format(str(type(contents))))

        self._add_config_to_store(identity, config_name, raw_data, contents, config_type,
                                  trigger_callback=trigger_callback, send_update=send_update)

    def _add_config_to_store(self, identity, config_name, raw, parsed, config_type, trigger_callback=False,
                             send_update=True):
        """Adds a processed configuration to the store."""
        agent_store = self.store.get(identity)

        action = "UPDATE"

        if agent_store is None:
            # Initialize a new store.
            store_path = os.path.join(self.store_path, identity + store_ext)
            store = PersistentDict(filename=store_path, flag="c", format="json")
            agent_store = {
                "configs": {},
                "store": store,
                "name_map": {},
                "lock": Semaphore(),
            }
            self.store[identity] = agent_store

        agent_configs = agent_store["configs"]
        agent_disk_store = agent_store["store"]
        agent_store_lock = agent_store["lock"]
        agent_name_map = agent_store["name_map"]

        config_name = strip_config_name(config_name)
        config_name_lower = config_name.lower()

        if config_name_lower not in agent_name_map:
            action = "NEW"

        if check_for_recursion(config_name, parsed, agent_configs):
            raise ValueError("Recursive configuration references detected.")

        if config_name_lower in agent_name_map:
            old_config_name = agent_name_map[config_name_lower]
            del agent_configs[old_config_name]

        agent_configs[config_name] = parsed
        agent_name_map[config_name_lower] = config_name

        agent_disk_store[config_name] = {
            "type": config_type,
            "modified": format_timestamp(get_aware_utc_now()),
            "data": raw,
        }

        agent_disk_store.async_sync()

        _log.debug("Agent {} config {} stored.".format(identity, config_name))

        if send_update and identity in self.vip.peerlist.peers_list:
            with agent_store_lock:
                try:
                    self.vip.rpc.call(
                        identity,
                        "config.update",
                        action,
                        config_name,
                        contents=parsed,
                        trigger_callback=trigger_callback,
                    ).get(timeout=UPDATE_TIMEOUT)
                except Unreachable:
                    _log.debug("Agent {} not currently running. Configuration update not sent.".format(identity))
                except RemoteError as e:
                    _log.error(
                        "Agent {} failure when adding/updating configuration {}: {}".format(identity, config_name, e))
                except MethodNotFound as e:
                    _log.error(
                        "Agent {} failure when adding/updating configuration {}: {}".format(identity, config_name, e))
                except gevent.timeout.Timeout:
                    _log.error("Config update to agent {} timed out after {} seconds".format(identity, UPDATE_TIMEOUT))
                except Exception as e:
                    _log.error("Unknown error sending update to agent identity {}.: {}".format(identity, e))

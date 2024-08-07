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

from collections import defaultdict
from datetime import datetime
import logging

from volttron.client.known_identities import CONTROL_CONNECTION, PROCESS_IDENTITIES
from volttron.types import ServiceInterface
from volttron.utils import format_timestamp
from volttron.client.vip.agent import Agent, Core, RPC

# TODO: rmq addition
# from volttron.utils.rmq_config_params import RMQConfig
# from volttron.utils.rmq_setup import start_rabbit, RabbitMQStartError
from volttron.services.auth.auth_service import AuthFile, AuthEntry

_log = logging.getLogger(__name__)


class HealthService(ServiceInterface):

    def __init__(self, **kwargs):
        super(HealthService, self).__init__(**kwargs)

        # Store the health stats for given peers in a dictionary with
        # keys being the identity of the connected agent.
        self._health_dict = defaultdict(dict)
        entry = AuthEntry(
            credentials=self.core.publickey,
            user_id=self.core.identity,
            capabilities=[{
                "edit_config_store": {
                    "identity": self.core.identity
                }
            }],
            comments="Automatically added on health service init"
        )
        AuthFile().add(entry, overwrite=True)

    def peer_added(self, peer):
        """
        The `peer_added` method should be called whenever an agent is connected to the
        platform.

        :param peer: The identity of the agent connected to the platform
        """
        health = self._health_dict[peer]

        health["peer"] = peer
        health["service_agent"] = peer in PROCESS_IDENTITIES
        health["connected"] = format_timestamp(datetime.now())

    def peer_dropped(self, peer):
        # TODO: Should there be an option for  a db/log file for agents coming and going from the platform?
        self._health_dict[peer]["disconnected"] = format_timestamp(datetime.now())
        del self._health_dict[peer]

    @RPC.export
    def get_platform_health(self):
        """
        The `get_platform_health` retrieves all of the connected agent's health structures,
        except for the `CONTROL_CONNECTION` (vctl's known identity).  Vctl's identity is used for short
        term connections and is not relevant to the core health system.

        This function returns a dictionary in the form identity: values such as the following:

        .. code-block :: json

            {
                "listeneragent-3.3_35":
                {
                    "peer": "listeneragent-3.3_35",
                    "service_agent": False,
                    "connected": "2020-10-28T12:46:58.701119",
                    "last_heartbeat": "2020-10-28T12:47:03.709605",
                    "message": "GOOD"
                }
            }

        :return:
        """
        # Ignore the connection from control in the health as it will only be around for a short while.
        agents = {
            k: v
            for k, v in self._health_dict.items() if not v.get("peer") == CONTROL_CONNECTION
        }
        return agents

    def _heartbeat_updates(self, peer, sender, bus, topic, headers, message):
        """
        This method is called whenever a publish goes on the message bus from the
        heartbeat* topic.

        :param peer:
        :param sender:
        :param bus:
        :param topic:
        :param headers:
        :param message:
        :return:
        """
        health = self._health_dict[sender]
        time_now = format_timestamp(datetime.now())
        if not health:
            health["connected"] = time_now
            health["peer"] = sender
            health["service_agent"] = sender in PROCESS_IDENTITIES

        health["last_heartbeat"] = time_now
        health["message"] = message

    @Core.receiver("onstart")
    def onstart(self, sender, **kwargs):
        # Start subscribing to heartbeat topic to get updates from the health subsystem.
        self.vip.pubsub.subscribe("pubsub", "heartbeat", callback=self._heartbeat_updates)

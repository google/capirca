#!/usr/bin/python
#
# Copyright 2013 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""A push implementation for Cisco Nexus(NX-OS) devices.

This module implements the base device interface of base_device.py for
Cisco NX-OS devices.
"""

__author__ = 'mijith@google.com (Mijith)'


import gflags

import paramiko_device
import push_exceptions as exceptions

FLAGS = gflags.FLAGS

gflags.DEFINE_float('cisconx_timeout_response', None,
                   'Cisco nexus device response timeout in seconds.')
gflags.DEFINE_float('cisconx_timeout_connect', None,
                   'Cisco nexus device connect timeout in seconds.')
gflags.DEFINE_float('cisconx_timeout_idle', None,
                   'Cisco nexus device idle timeout in seconds.')
gflags.DEFINE_float('cisconx_timeout_disconnect', None,
                   'Cisco nexus device disconnect timeout in seconds.')
gflags.DEFINE_float('cisconx_timeout_act_user', None,
                   'Cisco nexus device user activation timeout in seconds.')

INVALID_OUT = 'Cmd exec error.'
# eg:.
# [ mijith@pulsar: ~ ].
# $ ssh gmonitor@us-mtv-43-fabsw1.mtv 'foo'.
# Syntax error while parsing 'foo'.
#
# Cmd exec error.


class CiscoNexusDevice(paramiko_device.ParamikoDevice):
  """A base device model suitable for Cisco Nexus devices.

  See the base_device.BaseDevice method docstrings.
  """

  def __init__(self, **kwargs):
    self.vendor_name = 'cisconx'
    super(CiscoNexusDevice, self).__init__(**kwargs)

  def _Cmd(self, command, mode=None):
    """Cisco Nexus wrapper for ParamikoDevice._Cmd()."""

    result = super(CiscoNexusDevice, self)._Cmd(command, mode)
    # On Successful execution of a command.
    # ssh gmonitor@us-mtv-43-fabsw1.mtv 'show version'.
    # Password:.
    # Cisco Nexus Operating System (NX-OS) Software
    # TAC support: http://www.cisco.com/tac.
    # [output truncated].

    # Incomplete Command Example.
    # [ mijith@pulsar: ~ ].
    # $ ssh gmonitor@us-mtv-43-fabsw1.mtv 'show'
    # Syntax error while parsing 'show'.
    # Cmd exec error.

    # Invalid Command Example.
    # [ mijith@pulsar: ~ ].
    # $ ssh gmonitor@us-mtv-43-fabsw1.mtv 'foo'.
    # Syntax error while parsing 'foo'.
    # Cmd exec error.

    if result.endswith(INVALID_OUT):
      raise exceptions.CmdError('INVALID COMMAND: %s' % command)

    return result

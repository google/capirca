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
"""A Cisco XR device .

This module implements the base device interface of base_device.py for
CiscoXR devices.
"""


import gflags

import paramiko_device
import push_exceptions as exceptions

FLAGS = gflags.FLAGS

gflags.DEFINE_float('ciscoxr_timeout_response', None,
                   'CiscoXR device response timeout in seconds.')
gflags.DEFINE_float('ciscoxr_timeout_connect', None,
                   'CiscoXR device connect timeout in seconds.')
gflags.DEFINE_float('ciscoxr_timeout_idle', None,
                   'CiscoXR device idle timeout in seconds.')
gflags.DEFINE_float('ciscoxr_timeout_disconnect', None,
                   'CiscoXR device disconnect timeout in seconds.')
gflags.DEFINE_float('ciscoxr_timeout_act_user', None,
                   'CiscoXR device user activation timeout in seconds.')

# pylint: disable=arguments-differ
# 38:CiscoXrDevice._Cmd: Arguments number differs from overridden method.


class CiscoXrDevice(paramiko_device.ParamikoDevice):
  """A base device model suitable for CiscoXR devices.

  See the base_device.BaseDevice method docstrings.
  """

  def __init__(self, **kwargs):
    self.vendor_name = 'ciscoxr'
    super(CiscoXrDevice, self).__init__(**kwargs)

  def _Cmd(self, command, mode=None):
    """CiscoXR wrapper for ParamikoDevice._Cmd()."""

    result = super(CiscoXrDevice, self)._Cmd(command, mode)
    if result.endswith("% Invalid input detected at '^' marker.\r\n"):
      raise exceptions.CmdError('Invalid input: %s' % command)
    if result.endswith('% Bad hostname or protocol not running\r\n'):
      raise exceptions.CmdError(
          'Bad hostname or protocol not running: %s' % command)
    if result.endswith('% Incomplete command.\r\n'):
      raise exceptions.CmdError('Incomplete command: %s' % command)
    return result

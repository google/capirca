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
"""Fake classes for unit tests.

The class FakeSshClient is a fake for paramiko.SSHClient, it implements a very
minimal set of methods just enough too stub out paramiko.SSHClient when used in
unit test for clients based on pexpect_client.ParamikoSshConnection.
The classes FakeChannel and FakeTransport are substitutes for their paramiko
counterparts Channel and Transport.
"""
# pylint: disable=g-bad-name
class Error(Exception):
  pass


class FakeChannelError(Error):
  """An error occured in the fake Channel class."""


class FakeTransport(object):
  """A fake transport class for unit test purposes."""

  def __init__(self):
    self.active = True

  def is_active(self):
    return self.active


class FakeChannel(object):
  """A fake channel class for unit test purposes."""

  def __init__(self, command_response_dict):
    self.command_response_dict = command_response_dict
    self.transport = FakeTransport()
    self.timeout = None
    self.last_sent = '__logged_in__'

  def set_combine_stderr(self, unused_arg):
    pass

  def get_id(self):
    return 1

  def get_transport(self):
    return self.transport

  def settimeout(self, timeout):
    self.timeout = timeout

  def recv(self, unused_size):
    if self.last_sent:
      last_sent = self.last_sent
      self.last_sent = None
      if last_sent in self.command_response_dict:
        return self.command_response_dict[last_sent]
      else:
        raise FakeChannelError('unknown input %r' % last_sent)

  def send(self, command):
    self.last_sent = command


class FakeSshClient(object):
  """A fake SSH client class for unit test purposes."""

  def __init__(self, command_response_dict):
    self.channel = FakeChannel(command_response_dict)

  def Connect(self, **unused_kwargs):
    return self

  def invoke_shell(self):
    return self.channel

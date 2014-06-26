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
"""An abstract Paramiko SSH2 capable device model.

For devices that can use Paramiko SSH2, this device defines the connection
setup and teardown mechanisms. When sub-classing, you must define all API
methods you wish to implement. Others will return an NotImplemented Exception.
"""

import time
import gflags
import logging

import paramiko

import sshclient
import base_device
import push_exceptions as exceptions


FLAGS = gflags.FLAGS

# Remote channel ids greater than this trigger a reconnect. The higher this
# number, the more channels can be 'in flight' in a single session.
_LOW_CHANID_THRESHOLD = 1


class ParamikoDevice(base_device.BaseDevice):
  """A device model suitable for devices which support paramiko SSHv2.

  See the base_device.BaseDevice docstrings.
  """

  def __init__(self, **kwargs):
    super(ParamikoDevice, self).__init__(**kwargs)
    # Setup local state.
    self._ssh_client = None
    self._port = kwargs.get('port', 22)
    self._username = None
    self._password = None

  def _Connect(self, username, password=None, ssh_keys=None,
               enable_password=None, ssl_cert_set=None):
    _ = ssl_cert_set
    logging.debug('In Paramiko._Connect, host is %s, self._connected? %s'
                  '_ssh_client is None? %s', self.host, self._connected,
                  self._ssh_client is None)
    self._username = username
    self._password = password or self._password
    self._ssh_keys = ssh_keys or self._ssh_keys or ()
    self._enable_password = enable_password or self._enable_password

    self._ssh_client = sshclient.Connect(hostname=self.loopback_ipv4,
                                         username=self._username,
                                         password=self._password,
                                         port=self._port,
                                         ssh_keys=self._ssh_keys)
    return None

  def _GetConnected(self):
    """Sanity-checks the connected status prior to returning it.

    Returns:
      A bool, the connected status.
    """
    logging.debug('In ParamikoDevice._GetConnected, host is %s (?)', self.host)
    if self._connected:
      if (self._ssh_client is None or
          self._ssh_client.get_transport() is None or
          not self._ssh_client.get_transport().is_active()):
        self._connected = False
    return self._connected

  def _Disconnect(self):
    logging.debug('In ParamikoDevice._Disconnect, host is %s, '
                  'connected is %s, self._ssh_client is None? %s',
                  self.host, self._connected, self._ssh_client is None)
    if self.connected and self._ssh_client is not None:
      self._ssh_client.close()
      self._ssh_client = None
    return None

  def _Cmd(self, command, mode=None, merge_stderr_first=False, send=None,
           require_low_chanid=False):
    response = ''
    retries_left = 1
    while True:
      try:
        chan = self._ssh_client.get_transport().open_session()
        chan.settimeout(self.timeout_response)
        if require_low_chanid and chan.remote_chanid > _LOW_CHANID_THRESHOLD:
          # We should not be having multiple channels open. If we do,
          # close them before proceeding.
          logging.error(
              'Remote ssh channel id %d exceeded %d when opening session to '
              '%s(%s), reconnecting.',
              chan.remote_chanid, _LOW_CHANID_THRESHOLD, self.host,
              self.loopback_ipv4)
          self.Disconnect()
          self.Connect(self._username, self._password, self._ssh_keys,
                       self._enable_password)
          chan = self._ssh_client.get_transport().open_session()
        chan.exec_command(command)
        stdin = chan.makefile('wb', -1)
        stdout = chan.makefile('rb', -1)
        stderr = chan.makefile_stderr('rb', -1)
        if send is not None:
          stdin.write(send)
        stdout_data = stdout.read()
        stderr_data = stderr.read()

        # Request channel close by remote peer.
        chan.close()
        break
      except paramiko.SSHException as e:
        msg = str(e)
        logging.error('%s(%s) Cmd(%r, mode=%r): %s', self.host,
                      self.loopback_ipv4, command, mode, msg)
        raise exceptions.CmdError(msg)
      except AttributeError:
        # This occurs when self._ssh_client becomes None after a Paramiko
        # failure. Pause momentarily, try to reconnect and loop to resend
        # the command.
        time.sleep(0.25)
        try:
          if retries_left:
            self._Connect(self._username, self._password, self._ssh_keys)
            retries_left -= 1
            continue
          else:
            raise exceptions.CmdError('Failed to exec_command after retry.')
        except paramiko.SSHException as e:
          msg = str(e)
          logging.error('%s(%s) Cmd(%r, mode=%r): %s', self.host,
                        self.loopback_ipv4, command, mode, msg)
          raise exceptions.ConnectError(msg)
      except Exception as e:
        # Paramiko may raise any exception, so catch and log it here.
        msg = '%s:%s(%s) Cmd(%r, mode=%r): %s: %s' % (
            type(e), self.host, self.loopback_ipv4, command, mode,
            e.__class__.__name__, str(e))
        logging.exception(msg)
        raise exceptions.CmdError('%s: %s' % (e.__class__.__name__, str(e)))

    # Remove stderr lines started with 'waiting for'.
    if stderr_data and not merge_stderr_first:
      out = []
      for l in stderr_data.splitlines():
        if not l.startswith('waiting for'):
          out.append(l)
      stderr_data = '\n'.join(out)

    # Marshal the response from the stdout/err channels and handle errors.
    if stderr_data and not merge_stderr_first:
      raise exceptions.CmdError(stderr_data)
    elif stdout_data:
      if merge_stderr_first and stderr_data:
        response = stderr_data
      response += stdout_data
    else:
      # Sometimes, a command (e.g., 'show system license keys') returns
      # nothing.  This can mean that the channel went away on us, and we
      # got no data back (and no error).
      if self.connected:
        logging.warn('Both STDOUT and STDERR empty after %s on %s(%s)',
                     repr(command), self.host, self.loopback_ipv4)
      else:
        raise exceptions.CmdError('Connection to %s(%s) was terminated.' %
                                  (self.host, self.loopback_ipv4))
    return response

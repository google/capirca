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
"""An abstract device model.

Concrete implementations should be placed alongside this.

Concerete subclasses must implement all methods that have NotImplementedError
exceptions raised in this abstract interface.  Methods Lock and Unlock are
optional, so clients of the device classes should expect that a
NotSupportedError will potentially be raised.
"""

import time
import gflags
import push_exceptions as exceptions
import logging


FLAGS = gflags.FLAGS

gflags.DEFINE_float('host_down_sinbin_time',
                   180.0,
                   'Seconds that down hosts are placed in the sin-bin for.')

# Define the default timeout values for each vendor.
# Each vendor also provides the same flags (s/base/$VENDOR_NAME/),
# with None as the default value. See BaseDevice._SetupTimeouts.
gflags.DEFINE_float('base_timeout_response',
                    300.0,
                    'Default device response timeout in seconds.')
gflags.DEFINE_float('base_timeout_connect',
                    10.0,
                    'Default device connect timeout in seconds.')
gflags.DEFINE_float('base_timeout_idle',
                    600.0,
                    'Default device idle timeout in seconds.')
gflags.DEFINE_float('base_timeout_disconnect',
                    10.0,
                    'Default device disconnect timeout in seconds.')
gflags.DEFINE_float('base_timeout_act_user',
                    10.0,
                    'Default device user activation timeout in seconds.')
# The default for this is set to 180 seconds, so that it is the same as
# host_down_sinbin_time's default. This effectively disables the faster retries
# by default - the flag must be used to enable them.
gflags.DEFINE_float('base_device_initial_failure_delay', 180.0,
                    'If a device fails to connect, retry after '
                    'this many seconds at first, doubling each time '
                    'for frequent errors (only applies to whitelisted devices).')
gflags.DEFINE_float('base_device_failure_forgiveness_delay', 10 * 60,
                    'Forget connect failures that happened more than this many '
                    'seconds ago (only on whitelisted devices).')


class BaseDevice(object):
  """A skeleton base device referring to a specific device in the network.

  Notes:
    All methods other than Connect and Nop raise NotImplementedError as
    they are pure virtual methods.

    Methods that have arguments perform argument type testing prior to
    calling private implementations of their method.  Replace the private
    method in your implementation.

  Attributes:
    host: A string, the host name.
    loopback_ipv4: A string representation of the IPv4 address used for
      device management inside device modules.
    vendor: A string, the vendor, e.g., 'JUNIPER'.
    connected: A bool, whether we are connected to the device or not.
    active: A bool, whether we're active or not.
    rollout: A list of strings, active rollout tags for the device.
  """
  # A dict to map from vendor string to vendor class, e.g.,
  # {'FORCE10': ftos.FtosDevice}
  # This dict is updated by each concrete subclass at class load time (by
  # factory.py).
  vendor_classes = {}

  # Standardized strings defining types of configurations.
  CONFIG_RUNNING = 'running-config'
  CONFIG_STARTUP = 'startup-config'
  CONFIG_PATCH = 'patch-config'
  NON_FILE_DESTINATIONS = (CONFIG_RUNNING, CONFIG_STARTUP, CONFIG_PATCH)

  def __init__(self, **kwargs):
    # Use kwargs so that subclasses can extend this state via the factory.
    self.host = kwargs.get('host', None)
    self.loopback_ipv4 = kwargs.get('loopback_ipv4', None)
    self.accessproxy = kwargs.get('accessproxy', None)
    self.accessproxy_device_dict = {}
    self.role = kwargs.get('role', None)
    self.realm = kwargs.get('realm', None)
    self.notes = self.__class__.__name__
    # Default to true for active.
    self.active = kwargs.get('active', True)
    self.vendor = kwargs.get('vendor', None)
    self.rollout = kwargs.get('rollout', [])
    self._subclass = kwargs.get('subclass', False)
    # Connection details.
    self._username = kwargs.get('username', None)
    self._password = None
    self._ssh_keys = None
    self._enable_password = None
    self._ssl_cert_set = None
    # Boolean attribute containing the considered state of the device. (True=up)
    self._host_status = True
    # The time the host's up/down status changed.  If None, ignore this value.
    self._host_last_status_change = None
    # Connected boolean, accessed via property connected.
    self._connected = False

    # Our last-raised exception if not None.
    self.__exc = None
    # If we have been initialised directly, set our vendor name.
    if not hasattr(self, 'vendor_name'):
      self.vendor_name = 'base'
    # Some sub-classes override this.
    if not hasattr(self, 'unsupported_non_file_destinations'):
      self.unsupported_non_file_destinations = (self.CONFIG_PATCH,)
    # Setup timeouts.
    self._InitialiseTimeouts()

  def __del__(self):
    """Special delete method called on object garbage collection.

    Holders of device objects should call Disconnect() explicltly,
    rather than relying on disconnection by this method.

    A global Exception handler must ensure deletion of references to
    instances of this class.  Garbage collection will close device
    connections when it runs this method, but there are no guarantees it
    will be run for all classes at program exit.
    """
    if self.connected:
      logging.debug('Garbage collection disconnecting %r' % self.host)
      self.Disconnect()

  def __str__(self):
    return '%s(host=%s, vendor=%s, role=%s)' % (
        self.__class__.__name__,
        repr(self.host),
        repr(self.vendor),
        repr(self.role))

  def _InitialiseTimeouts(self):
    """Sets up timeouts by scanning module flags.

    Subclasses must provide a _SetTimeouts method, to be called at the
    end of initialization.
    """
    for var in ('connect', 'response', 'idle', 'disconnect', 'act_user'):
      flag_name = '%s_timeout_%s' % (self.vendor_name, var)
      default_flag_name = 'base_timeout_%s' % var

      if getattr(FLAGS, flag_name) is not None:
        value = getattr(FLAGS, flag_name)
        setattr(self, 'timeout_%s' % var, value)
      else:
        default_value = getattr(FLAGS, default_flag_name)
        setattr(self, 'timeout_%s' % var, default_value)
    # Allow devices to optionally override timeouts.
    self._SetupTimeouts()

  def _SetupTimeouts(self):
    """Optionally setup device specific timeout value logic.

    If more than a global and device module specific timeout value are
    required (e.g., to set a minima), implement this method in the
    concrete device module. It need not be provided otherwise.
    """
    pass

  def _HostDownPrepareConnect(self):
    """Works out if it's safe to retry a connection attempt.

    Raises an exception if we're not prepared to retry the connection attempt.
    See also Connect, and HandleConnectFailure.

    Raises:
      The last exception class recorded in self.__exc.
    """
    now = time.time()
    time_left = self._dampen_end_time - now
    logging.debug('BaseDevice.Connect is waiting because of previous '
                  'connection errors, host is %s, time_left is %s',
                  self.host, time_left)
    if time_left > 0:
      # pylint: disable=g-doc-exception
      raise self.__exc.__class__(
          'Connection to %s(%s) failed. Will not retry for %.1fs.'
          % (self.host, self.loopback_ipv4, time_left),
          dampen_connect=True)
      # pylint: enable=g-doc-exception
    else:
      # Next time, we'll try to connect.
      self._host_status = True
      self.connected = False

  def Connect(self, username, password=None, ssh_keys=None,
              enable_password=None, ssl_cert_set=None):
    """Sets up a connection to the device.

    Concrete classes must implement _Connect() instead, with the same arguments.

    Concrete classes are expected not to disconnect the connection until it
    is cleaned-up by Disconnect().  A generic exception handler at the top-
    level should ensure sessions have an opportunity to be cleaned-up upon
    abnormal program termination.

    Args:
      username: A string, the username (role account) to use.
      password: A string, the password to use (optional; may be None).
      ssh_keys: A tuple of strings, SSH private keys (optional; may be None).
      enable_password: A string, an optional enable password (may be None).
      ssl_cert_set: An optional SSLCertificateSet protobuf (may be None).

    Raises:
      exceptions.ConnectError: the connection could not be established.
      exceptions.AuthenticationError: A device authentication error occurred, or
        neither a password nor an SSH private key was supplied.
    """
    # Either an SSH key or password must be supplied for authentication.
    if password is None and not ssh_keys and not ssl_cert_set:
      raise exceptions.AuthenticationError(
          'Cannot connect. No authentication information provided to device '
          'Connect method.')

    self._username = username
    self._password = password
    self._ssh_keys = ssh_keys or ()
    self._enable_password = enable_password
    self._ssl_cert_set = ssl_cert_set

    if not self.loopback_ipv4 and not self.accessproxy_device_dict:
      raise exceptions.ConnectError(
          'Device %r, or any access proxies, need to have an IPv4 '
          'management address.'
          % self.host)

    logging.debug('In BaseDevice.Connect, host is %s, _connected is %s',
                  self.host, self._connected)
    while not self.connected:
      try:
        if self._host_status:
          logging.debug('CONNECTING %s(%s)',
                        self.host, self.loopback_ipv4)
          self._Connect(username, password=password, ssh_keys=self._ssh_keys,
                        enable_password=enable_password,
                        ssl_cert_set=ssl_cert_set)
          self.connected = True
          logging.debug('CONNECTED %s(%s)',
                        self.host, self.loopback_ipv4)
          self._last_failure_time = None
        else:
          self._HostDownPrepareConnect()
      except (exceptions.ConnectError,
              exceptions.AuthenticationError), e:
        logging.error('CONNECT FAILURE %s(%s)',
                      self.host, self.loopback_ipv4)
        self._host_status = False
        self.__exc = e
        raise
    logging.debug('Leaving BaseDevice.Connect, host is %s, _connected is %s',
                  self.host, self._connected)
    return None

  def Nop(self, name):
    """No-operation.

    Args:
      name: A string, the (no) operation's name.

    Returns:
      A string, some output (can be ignored by the client).
    """
    msg = 'No-operation request named `%s` received.' % name
    logging.debug('ActionRequest: NOP %s %s', str(self.__class__), repr(msg))
    return msg

  def Cmd(self, command, mode=None):
    """Executes a command.

    Concrete classes must define _Cmd with the same arguments.

    Args:
      command: A string, the command to execute.
      mode: A string, the CLI mode to use for this command (e.g., 'shell'
        on Netscaler). The empty string or None will use the device's
        default mode.

    Returns:
      A string, the response.

    Raises:
      exceptions.CmdError: An error occurred inside the call to _Cmd.
    """
    if not command:
      raise exceptions.CmdError('No command supplied for Cmd() method.')
    else:
      if not mode:
        mode = None
      return self._Cmd(command, mode=mode)

  def GetConfig(self, source):
    """Returns a configuration file from the device.

    Concrete classes must define _GetConfig with the same arguments.

    Args:
      source: A string, representing either a path to a configuration file or a
        string to be interpreted by the device module.  For readability,
        consider using CONFIG_RUNNING and CONFIG_STARTUP to represent the
        generic concepts of the running and startup configurations.

    Returns:
      A string, the configuration file.  (This may be large).

    Raises:
      GetConfigError: the GetConfig operation failed.
      EmptyConfigError: the operation produced an empty configuration.
    """
    return self._GetConfig(source)

  def SetConfig(self, destination_file, data, canary,
                juniper_skip_show_compare=False,
                juniper_skip_commit_check=False,
                juniper_get_rollback_patch=False):
    """Updates a devices' configuration.

    Concrete classes must define _SetConfig with the same arguments.

    Args:
      destination_file: A string.  A path to a file on the device.
      data: A string, the configuration data to set.
      canary: A boolean, whether to canary, rather than set, the configuration.
      juniper_skip_show_compare: A boolean, temporary flag to skip
          'show | compare' on Junipers due to a bug.
      juniper_skip_commit_check: A boolean, flag to skip 'commit check' on
          Junipers when doing a canary.
      juniper_get_rollback_patch: A boolean, optionally try to retrieve a
          patch to rollback the config change.

    Returns:
      A SetConfigResult.  Transcript of any device interaction that occurred
      during the operation, plus any optional extras.

    Raises:
      exceptions.SetConfigError: the SetConfig operation failed.
      exceptions.SetConfigSyntaxError: the configuration data had a syntax
          error.
    """
    if destination_file in self.unsupported_non_file_destinations:
      raise exceptions.SetConfigError(
          '%s devices do not support %s as a destination.' %
          (self.vendor_name, destination_file))
    if ((juniper_skip_show_compare or
         juniper_skip_commit_check or
         juniper_get_rollback_patch) and
        self.__class__.__name__ == 'JunosDevice'):
      return self._SetConfig(destination_file, data, canary,
                             skip_show_compare=juniper_skip_show_compare,
                             skip_commit_check=juniper_skip_commit_check,
                             get_rollback_patch=juniper_get_rollback_patch)
    else:
      return self._SetConfig(destination_file, data, canary)

  def Disconnect(self):
    """Disconnects from the device.

    Concrete classes must define _Disconnect.

    This method is called by the class __del__ method, and should also be
    called by any global Exception handler (as __del__() is not guaranteed to
    be called when the Python interpreter exits).

    Disconnect is also called by the Device Manager during garbage collection.

    Raises:
      exceptions.DisconnectError if the disconnect operation failed.
    """
    self._Disconnect()
    self.connected = False
    logging.debug('DISCONNECTED %s(%s)',
                  self.host, self.loopback_ipv4)

  def _GetConnected(self):
    return self._connected

  def _SetConnected(self, c):
    logging.debug('Setting connected property on host %s to %s',
                  self.host, c)
    self._connected = c

  # Property for the connection status.
  connected = property(_GetConnected, _SetConnected)


class SetConfigResult(object):
  """Results of one SetConfig, including transcript and any optional extras.

  Attributes:
    transcript: A string, the chatter from the router and/or any error text.
    rollback_patch: None or a string, the optional rollback patch, if supported.
  """

  def __init__(self):
    self.transcript = ''
    self.rollback_patch = None

  def __len__(self):
    return len(self.transcript) + len(self.rollback_patch or '')

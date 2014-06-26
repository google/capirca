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
"""Commmon helper methods for creating an SSH connection."""

import cStringIO
import push_exceptions as exceptions
import gflags
import logging
import paramiko
import socket
import threading


gflags.DEFINE_string('paramiko_ssh_config',
                     '',
                     'Use this file to pass options using the same format as '
                     'OpenSSH.')

FLAGS = gflags.FLAGS

TIMEOUT_DEFAULT = 20.0


class Error(Exception):
  pass


class ScpError(Error):
  """An error occurred while attempting a SCP copy."""


class ScpTimeoutError(ScpError):
  """A device failed to respond to a SCP command within the timeout."""


class ScpMinorError(ScpError):
  """A device reported a SCP minor error."""


class ScpMajorError(ScpError):
  """A device reported a SCP major error."""


class ScpProtocolError(ScpError):
  """An unexpected SCP error occurred."""


class ScpChannelError(ScpError):
  """An error occurred with the SCP channel."""


class ScpClosedError(ScpError):
  """A device closed the SCP connection."""


class SshConfigError(ScpError):
  """The configuration file is either missing or malformed."""


class SshOptions(object):
  """Singleton wrapper class around the SSH configuration.

  This class creates a SSHOption object if the command line flag
  --paramiko_ssh_config was found and store the result for future
  use. Since this class is called from several threads, it uses a lock
  to protect concurrent attempts to load the configuration.
  """
  _lock = threading.Lock()
  _need_init = True
  _ssh_options = None

  def __init__(self):
    """Read the configuration if present and store it for later.

    Check if the flag --paramiko_ssh_config was set and parse the
    configuration file.
    """

    # This flag may be set by another thread concurrently. We will
    # check the value again under a lock.
    if SshOptions._need_init:
      try:
        with SshOptions._lock:
          if SshOptions._need_init and FLAGS.paramiko_ssh_config:
            logging.debug(
                'Reading configuration from %s', FLAGS.paramiko_ssh_config)

            try:
              configfile = open(FLAGS.paramiko_ssh_config)
              ssh_config = paramiko.SSHConfig()
              ssh_config.parse(configfile)
              SshOptions._ssh_options = ssh_config
            except Exception as e:  # pylint: disable=broad-except
              # Unfortunately paramiko raises "Exception" if there is an
              # error in the config file.
              logging.fatal('Unable to read or parse "%s": %s',
                            FLAGS.paramiko_ssh_config, e)
      finally:
        SshOptions._need_init = False

  def Lookup(self, hostname, port, username):
    """Translate the hostname, port and username using the configuration.

    If the port is not defined, 22 is used. If the username is not
    defined and no option override it, it will remain undefined.

    Args:
      hostname: A string, the hostname to use as the key for searching the
      configuration.
      port: An integer, the TCP port to used to reach the device. If not
      defined, the default value (22) will be returned.
      username: A string, the username to use to connect to the device. It
      will only be overridden if not defined.
    Returns:
      A tuple of (string, int, string) containing the new (hostname, port,
      username).
    """

    new_hostname = hostname
    new_port = port
    new_username = username

    if SshOptions._ssh_options:
      # We can't arrive here without first executing __init__, so we
      # can assume that the _ssh_option is set and we don't need a
      # lock since we're only doing readonly accesses.
      host_config = SshOptions._ssh_options.lookup(hostname)
      if host_config:
        if 'hostname' in host_config:
          new_hostname = host_config['hostname']

        if (not new_port or new_port == 22) and 'port' in host_config:
          try:
            new_port = int(host_config['port'])
          except ValueError:
            raise SshConfigError('Invalid port value %s for %s' %
                                 (host_config['port'], hostname))

        if not new_username and 'user' in host_config:
          new_username = host_config['user']

        logging.debug(
            'Translating %s:%s to %s:%s', hostname, port, new_hostname,
            new_port)

    if not new_port:
      new_port = 22

    return (new_hostname, new_port, new_username)


def Connect(hostname, username, password=None, port=22, ssh_keys=(),
            timeout=TIMEOUT_DEFAULT):
  """Makes a paramiko SSH connection to a device.

  Args:
    hostname: A string, the hostname or IP address to connect to.
    username: A string, the username to use on the connection.
    password: A string, the password to use on the connection.
    port: An int, the port number to connect to.
    ssh_keys: A tuple of strings, SSH private keys (optional; may be None).
    timeout: A float, the number of seconds before a connection times out.

  Returns:
    A paramiko.SSHClient() instance
  """

  options = SshOptions()
  hostname, port, username = options.Lookup(hostname, port, username)
  ssh_client = None

  def RaiseError(e, msg):
    """Raises an exception, disconnecting the SSH client.

    Args:
      e: An Exception.
      msg: An object, exception arguments.
    """
    raise e(msg)

  try:
    ssh_client = paramiko.SSHClient()
    # Always auto-add remote SSH host keys.
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client.load_system_host_keys()
    # Connect using paramiko with a timeout parameter (requires paramiko 1.7)
    if ssh_keys:
      pkeys = []
      for key in ssh_keys:
        logging.debug('Using SSH private key for device authentication.')
        # Use a virtual temporary file to store the key.
        ssh_key_fileobj = cStringIO.StringIO()
        ssh_key_fileobj.write(key)
        ssh_key_fileobj.reset()
        try:
          pkeys.append(paramiko.DSSKey(file_obj=ssh_key_fileobj))
          logging.debug('Using SSH DSA key for %r', hostname)
        except (IndexError, paramiko.SSHException) as e:
          if (isinstance(e, IndexError) or
              'not a valid DSA private key file' in str(e)):
            ssh_key_fileobj.reset()
            try:
              logging.debug('Using SSH RSA key for %r', hostname)
              pkeys.append(paramiko.RSAKey(file_obj=ssh_key_fileobj))
            except (IndexError, paramiko.SSHException) as e:
              raise exceptions.AuthenticationError(str(e))
          else:
            raise exceptions.ConnectError('SSHException: %s' % str(e))
    else:
      logging.debug('Using password for %r', hostname)
      pkeys = [None]
    for pkey in pkeys:
      saved_exception = None
      try:
        ssh_client.connect(hostname=hostname,
                           port=port,
                           username=username,
                           password=password,
                           pkey=pkey,
                           timeout=timeout,
                           allow_agent=False,
                           look_for_keys=False)
        break
      except (paramiko.AuthenticationException, paramiko.SSHException) as e:
        saved_exception = e
    if saved_exception is not None:
      raise saved_exception  # pylint: disable=raising-bad-type
    transport = ssh_client.get_transport()
    # Sometimes we have to authenticate a second time, eg. on Force10
    # we always fail the first authentication (if we try pkey + pass,
    # the pass succeeds; but if we do pass only, we have to do it
    # twice).  connect() above will have authenticated once.
    if not transport.is_authenticated():
      if pkeys != [None]:
        for pkey in pkeys:
          try:
            transport.auth_publickey(username, pkey)
            break
          except paramiko.SSHException:
            pass
    if not transport.is_authenticated():
      if password is not None:
        try:
          transport.auth_password(username, password)
        except paramiko.SSHException:
          pass
    if not transport.is_authenticated():
      msg = 'Not authenticated after two attempts on %r' % hostname
      RaiseError(exceptions.ConnectError, msg)
  except EOFError:
    msg = 'EOFError connecting to: %r' % hostname
    RaiseError(exceptions.ConnectError, msg)
  except paramiko.AuthenticationException as e:
    msg = 'Authentication error connecting to %s: %s' % (hostname, str(e))
    RaiseError(exceptions.AuthenticationError, msg)
  except paramiko.SSHException as e:
    msg = 'SSHException connecting to %s: %s' % (hostname, str(e))
    RaiseError(exceptions.ConnectError, msg)
  except socket.timeout as e:
    msg = 'Timed-out while connecting to %s: %s' % (hostname, str(e))
    RaiseError(exceptions.ConnectError, msg)
  except socket.error as e:
    msg = 'Socket error connecting to %r: %s %s' % (hostname, e.__class__, e)
    RaiseError(exceptions.ConnectError, msg)

  return ssh_client


def _ScpRecvResponse(channel):
  """Receives a response on a SCP channel.

  Args:
    channel: A Paramiko channel object.

  Raises:
    ScpClosedError: If the device has closed the connection.
    ScpMajorError: If the device reports a major error.
    ScpMinorError: If the device reports a minor error.
    ScpProtocolError: If an unexpected error occurs.
    ScpTimeoutError: If no response is received within the timeout.
  """
  buf = channel.recv(1)
  while True:
    if channel.recv_stderr_ready():
      # Dodgy: Cisco sometimes *ask* for a password, but they don't actually
      err = channel.recv_stderr(512)
      if err == 'Password: ':
        logging.warn('Password prompt received on SCP stderr, assuming '
                     'IOS bug (ignoring)')
      else:
        raise ScpProtocolError('Data on stderr: %r' % err)

    if not buf:
      raise ScpClosedError('Connection closed by remote device')

    if buf == '\x00':
      # Code \x00 indicates success.  Brocade have been observed sending
      # \x00\x02 followed by an error message, so we need to only read
      # the single \x00 and leave the error message to be handled in a
      # future call to _ScpRecvResponse.
      return

    try:
      extra = channel.recv(512)
      if not extra:
        raise ScpProtocolError(
            'Connection closed by remote device; partial response: %r' % buf)
      else:
        buf += extra
    except socket.timeout:
      if buf:
        raise ScpProtocolError(
            'Timed out reading from socket; partial response: %r' % buf)
      else:
        raise ScpTimeoutError('Timed out reading from socket')

    if buf[-1] == '\n':
      if buf[0] == '\x01':
        if buf.startswith('\x01File ') and buf.rstrip().endswith(
            'created successfully.'):
          return
        raise ScpMinorError(buf[1:-1])
      elif buf[0] == '\x02':
        # Code \x02: Fatal error.
        raise ScpMajorError(buf[1:-1])
      else:
        # Default case: Fatal error.
        raise ScpMajorError(buf[:-1])


def ScpPut(transport, source_data, destination_file, timeout, send_buffer=8192):
  """Puts a file via SCP protocol.

  Args:
    transport: A Paramiko transport object.
    source_data: The source data to copy as a string.
    destination_file: The file on the remote device.
    timeout: The timeout to use for the SCP channel.
    send_buffer: The number of bytes to send in each operation.

  Raises:
    ConnectionError: There was an error trying to start the SCP connection.
    ScpError: There was an error copying the file.
  """
  channel = transport.open_session()
  try:
    channel.settimeout(timeout)
    channel.exec_command('scp -t %s' % destination_file)

    # Server must acknowledge our connection.
    _ScpRecvResponse(channel)

    # Send file attributes, length and a dummy source file basename.
    source_size = len(source_data)
    channel.sendall('C0644 %d 1\n' % source_size)

    # Server must acknowledge our request to send.
    _ScpRecvResponse(channel)

    # Send the data in chunks rather than all at once
    pos = 0
    while pos < source_size:
      channel.sendall(source_data[pos:pos + send_buffer])
      pos += send_buffer

    # Indicate that we experienced no errors while sending.
    channel.sendall('\0')

    # Get the final status back from the device.  Note: Force10 actually sends
    # final status prior to getting the "all OK" from us.
    _ScpRecvResponse(channel)
  finally:
    try:
      channel.close()
    except EOFError:
      raise ScpChannelError('Error closing SCP channel')

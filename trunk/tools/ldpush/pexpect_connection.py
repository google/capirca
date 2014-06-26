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
"""Connections via pexpect to SSH and Telnet endpoints.

By deliberate side-effect, this module overwrites pexpect.spawn.__select
with an implementation based on poll(), to support use with higher file
descriptors than supported by select().
"""

import errno
import os
import re
import select
import socket
import time

import paramiko
import pexpect

import gflags
import logging

import sshclient
import push_exceptions as exceptions

FLAGS = gflags.FLAGS

TIMEOUT_DEFAULT = 20.0


class Error(Exception):
  pass


class ConnectionError(Error):
  """The connection failed due to an error."""


class TimeoutError(Error):
  """The operation timed-out."""


class OperationFailedError(Error):
  """The sub-process had a non-zero exit status."""


class ScpError(Error):
  """An error occurred during an SCP operation."""


def _SelectViaPoll(_, rfds, wfds, efds, timeout):
  """poll() based replacement for pexpect.spawn.__select().

  As mentioned in the module docstring, this is required since Python's select
  is unable to wait for events on high-numbered file descriptors.  The API is
  as per select.select(), however if we are interrupted by a signal, we wait
  again for the remaining time.

  Args:
    _: An object, self, unused.
    rfds: A list, file descriptors to check for read.
    wfds: A list, file descriptors to check for write.
    efds: A list, file descriptors to check for exceptions.
    timeout: A float, timeout (seconds).

  Returns:
    A tuple of three lists, being the descriptors in each of the incoming lists
    which are ready for read, write or have an exception, respectively.
  """
  if wfds or efds:
    logging.fatal('Unexpected code change in pexpect: __select '
                  'called with wfds=%s efds=%s', wfds, efds)
  p = select.poll()
  for fd in rfds:
    p.register(fd, select.POLLIN)

  # See pexpect.spawn.__select for timeout handling logic; this is the same
  # in select() and poll(), except that the timeout argument to poll() is
  # in milliseconds.  poll() raises the same exception on timeout as select().
  if timeout is not None:
    end_time = time.time() + timeout
  while True:
    try:
      fdstate = p.poll(int(timeout * 1000) if timeout is not None else None)
      # Build a list of descriptors which select() would return as 'available
      # for read' (which includes EOF conditions which may be indicated as
      # POLLIN, POLLHUP or POLLIN|POLLHUP, depending on the type of file
      # descriptor).
      rrfds = []
      for fd, state in fdstate:
        if state & select.POLLIN or state & select.POLLHUP:
          rrfds.append(fd)
      return (rrfds, [], [])
    except select.error as e:
      if e[0] == errno.EINTR:
        if timeout is not None:
          timeout = end_time - time.time()
          if timeout < 0:
            return ([], [], [])
      else:
        raise

# Override pexpect.spawn.__select as mentioned in module docstring.
pexpect.spawn._spawn__select = _SelectViaPoll


class Connection(object):
  """The base class for pexpect connections."""

  def __init__(self, host, username, password=None, success=None,
               connect_command=None, timeout=None, find_prompt=False,
               enable_password=None, find_prompt_prefix=None):
    """Initializer.

    Args:
      host: A string, the hostname or IP address to connect to.
      username: A string, the username to use on the connection.
      password: A string, the password to use on the connection.
      success: A string, the string to expect to trigger successful completion.
      connect_command: A string, the command to connect (minus the host suffix).
      timeout: A float, the number of seconds before a connection times out.
      find_prompt: A bool, if true then success is a regexp and it's group(1)
        should be used to build self._prompt.
      enable_password: A string, the enable password to optionally use.
      find_prompt_prefix: A string, the prefix to put before group(1) from the
        success regexp to build self._prompt, if find_prompt is true.
    """
    self._connect_timeout = timeout or TIMEOUT_DEFAULT
    self._host = host
    self._username = username
    self._password = password
    self._success = success
    self._find_prompt = find_prompt
    self._connect_command = connect_command
    self._enable_password = enable_password
    self._find_prompt_prefix = (
        r'(?:^|\n)' if find_prompt_prefix is None else find_prompt_prefix)
    self.child = None

  def _MaybeFindPrompt(self):
    if self._find_prompt:
      try:
        self._prompt = self._find_prompt_prefix + re.escape(
            self.child.match.group(1))
        self.re_prompt = re.compile(self._prompt)
        logging.debug('%s: prompt set to %r', self._host, self._prompt)
      except IndexError:
        logging.debug('%s: find_prompt set but no capture group - skipping',
                      self._host)


class SocketSpawn(pexpect.spawn):
  """Wrapper around pexpect.spawn to use a supplied socket.

  This class does not close the file; it assumes it is a Python socket
  which will be held/destroyed by the caller.
  """
  # pylint: disable=g-bad-name

  def __init__(self, sock, *args, **kwargs):
    pexpect.spawn.__init__(self, None, *args, **kwargs)
    self.child_fd = sock.fileno()
    self.closed = False
    self.name = '<file descriptor %d>' % self.child_fd

  def isalive(self):
    if self.child_fd == -1:
      return False
    try:
      os.fstat(self.child_fd)
      return True
    except OSError:
      return False

  def __del__(self):
    return

  def close(self):
    return

  def terminate(self, force=False):
    _ = force
    return

  def kill(self, sig):
    _ = sig
    return


class SocketConnection(Connection):
  """IPv4 TCP socket connection class."""

  def __init__(self, host, port, username, password=None, success=None,
               timeout=None, initial_chat=None, find_prompt=False,
               find_prompt_prefix=None):
    """Creates an IPv4 TCP socket connection.

    Args:
      host: As per parent.
      port: An int, the port number to connect to.
      username: As per parent.
      password: As per parent.
      success: As per parent.
      timeout: As per parent.
      initial_chat: A tuple of tuples, each tuple in this list is a string
        to expect from the socket and a response; the chat must occur in the
        exact order specified.  Intended only for telnet option negotiation.
      find_prompt: As per parent.
      find_prompt_prefix: As per parent.
    """
    super(SocketConnection, self).__init__(
        host, username=username, password=password, success=success,
        timeout=timeout, find_prompt=find_prompt,
        find_prompt_prefix=find_prompt_prefix)
    self._port = port
    self._initial_chat = initial_chat
    self._connect_timeout = timeout or TIMEOUT_DEFAULT
    if success is None:
      self._success = self._username+r'.*> '

  def Connect(self):
    """Makes the connection."""
    self._sock = socket.socket()
    self._sock.settimeout(self._connect_timeout)
    try:
      self._sock.connect((self._host, self._port))
    except socket.timeout:
      raise TimeoutError(self._connect_timeout)
    except socket.gaierror as e:
      raise ConnectionError('Lookup failure for %r: %s' % (self._host, e[1]))
    except socket.error as e:
      raise ConnectionError('Connect failure for %r: %s' % (self._host, e[1]))

    if self._initial_chat is not None:
      try:
        for expected_recv, to_send in self._initial_chat:
          actual_recv = self._sock.recv(len(expected_recv))
          if actual_recv == expected_recv:
            self._sock.send(to_send)
          else:
            raise ConnectionError('Initial chat failure for %r: expected %r, '
                                  'got %r' % (self._host, expected_recv,
                                              actual_recv))
      except socket.timeout:
        logging.debug('Initial chat timeout for %r', self._host)
        raise TimeoutError(self._connect_timeout)

    self._sock.settimeout(None)
    self.child = SocketSpawn(self._sock, maxread=8192)
    self.child.timeout = self._connect_timeout
    logging.debug('Socket connected to %r:%s', self._host, self._port)

    responses = self.child.compile_pattern_list([
        self._success,
        r'[Ll]ogin|[Uu]ser[Nn]ame',
        r'[Pp]assword:',
        r'Permission denied|Authentication failed'])
    self.exit_list = self.child.compile_pattern_list(pexpect.EOF)

    while True:
      try:
        timeout = max(1, self._connect_timeout)
        pattern = self.child.expect_list(responses, timeout=timeout)
        logging.debug('Connect() matched responses[%d]', pattern)
        if pattern == 0:
          self._MaybeFindPrompt()
          break
        elif pattern == 1:
          self.child.send(self._username+'\r')
        elif pattern == 2:
          self.child.send(self._password+'\r')
        elif pattern == 3:
          raise ConnectionError('Permission denied for %r' % self._host)
        else:
          raise ConnectionError('Unexpected pattern %d' % pattern)
      except pexpect.TIMEOUT:
        raise TimeoutError(timeout)
      except pexpect.EOF as e:
        raise ConnectionError(str(e))
    return None


class SshSpawn(pexpect.spawn):
  """Wrapper around pexpect.spawn to use a Paramiko channel."""
  # pylint: disable=g-bad-name

  def __init__(self, channel, *args, **kwargs):
    pexpect.spawn.__init__(self, None, *args, **kwargs)
    self.channel = channel
    self.child_fd = None
    self.closed = False
    self.name = '<ssh channel %s>' % channel.get_id()

  def isalive(self):
    try:
      return self.channel.get_transport().is_active()
    except AttributeError:
      return False

  def read_nonblocking(self, size=1, timeout=None):
    """See parent.  This actually may or may not block based on timeout."""
    if not self.isalive():
      raise pexpect.EOF('End Of File (EOF) in read() - Not alive.')

    if timeout == -1:
      timeout = self.timeout

    self.channel.settimeout(timeout)
    try:
      s = self.channel.recv(size)
    except socket.timeout:
      raise pexpect.TIMEOUT('Timeout (%s) exceeded in read().' % timeout)
    except paramiko.SSHException as e:
      raise pexpect.EOF('Paramiko exception: %s' % e)
    except EOFError:
      raise pexpect.EOF('Paramiko reported End Of File (EOF) in read()')
    if not s:
      self.flag_eof = 1
      raise pexpect.EOF('End Of File (EOF) in read().')
    return s

  def send(self, s):
    return self.channel.send(s)

  def __del__(self):
    return

  def close(self):
    return

  def terminate(self, force=False):
    _ = force
    return

  def kill(self, sig):
    _ = sig
    return


class HpSshSpawn(SshSpawn):
  """Wrapped pexpect.spawn to use a Paramiko channel and HP ANSI filters.

  This also deals with the annoying pager which cannot be disabled.
  """
  # ANSI character sequences to convert to a newline.
  NEWLINE_RE = re.compile('\x1B(?:\\[0m|E)')

  # All other ANSI character sequences (removed from the output).
  # Matches all strings containing \x1B, unless they contain a truncated ANSI
  # sequence at the end of the string.
  ANSI_RE = re.compile('\x1B([^[]|\\[[^@-~]*[@-~])')

  def __init__(self, channel, *args, **kwargs):
    SshSpawn.__init__(self, channel, *args, **kwargs)
    self._read_nonblocking_buf = ''

  def _Filter(self, text):
    text = re.sub(self.NEWLINE_RE, '\n', text)
    text = re.sub(self.ANSI_RE, '', text)
    logging.vlog(4, 'Filtered: %r', text)
    return text

  def read_nonblocking(self, size=1, timeout=None):
    """Read, handling terminal control input from an HP ProCurve.

    This may or may not actually block, as per its parent.

    Args:
      size: An int, the minimum size block to return.
      timeout: An optional float, wait only timeout seconds at most.

    Returns:
      A string, the filtered output.
    """
    start = time.time()
    if timeout == -1:
      timeout = self.timeout
    while True:
      if timeout and time.time() > start + timeout:
        return ''
      in_data = SshSpawn.read_nonblocking(self, size=size, timeout=timeout)
      logging.vlog(4, 'Unfiltered: %r', in_data)
      if in_data and self._read_nonblocking_buf:
        logging.debug('Prepending data: %r', self._read_nonblocking_buf)
        in_data = self._read_nonblocking_buf + in_data
        self._read_nonblocking_buf = ''
      filtered = self._Filter(in_data)
      escape_location = filtered.find('\x1B')
      if escape_location != -1:
        logging.debug('Partial ANSI tag in filtered data: %r', filtered)
        self._read_nonblocking_buf = filtered[escape_location:]
        filtered = filtered[:escape_location]
      if filtered:
        return filtered


class ParamikoSshConnection(Connection):
  """Base class for SSH connections using Paramiko."""

  def __init__(self, host, username, password=None, success=None,
               timeout=None, find_prompt=False, ssh_keys=None,
               enable_password=None, ssh_client=None, find_prompt_prefix=None):
    """Initializer.

    Args:
      host: As per parent.
      username: As per parent.
      password: As per parent.
      success: As per parent.
      timeout: As per parent.
      find_prompt: As per parent.
      ssh_keys: A tuple of strings, SSH private keys (optional; may be None).
      enable_password: As per parent.
      ssh_client: A instance of an object that implements an SSH client.
      find_prompt_prefix: As per parent.
    """
    super(ParamikoSshConnection, self).__init__(
        host, username, password, success, None, timeout, find_prompt,
        enable_password=enable_password, find_prompt_prefix=find_prompt_prefix)
    if success is None:
      self._success = self._username+r'.*> '
    self.ssh_client = ssh_client
    self._ssh_client = None
    self._ssh_keys = ssh_keys or ()
    self._spawn = SshSpawn
    if self._spawn is None:
      raise NotImplementedError('Must supply a spawn= keywoard argument.')

  def Connect(self):
    """Makes the connection.

    We can have an instance of this class without being connected to the
    device, e.g. after a disconnect. Hence setting up the actual SSH connection
    should happen in this method, not in the constructor.
    """
    try:
      if self.ssh_client:
        # An SSH client was provided. Use it.
        self._ssh_client = self.ssh_client.Connect(
            hostname=self._host,
            username=self._username,
            password=self._password,
            ssh_keys=self._ssh_keys,
            timeout=self._connect_timeout)
      else:
        # The Connect() function from the sshclient module is a factory that
        # returns a paramiko.SSHClient instance.
        self._ssh_client = sshclient.Connect(
            hostname=self._host,
            username=self._username,
            password=self._password,
            ssh_keys=self._ssh_keys,
            timeout=self._connect_timeout)
    except (exceptions.ConnectError, exceptions.AuthenticationError) as e:
      raise ConnectionError(str(e))
    # We are connected. Now set up pexpect.
    try:
      ssh_channel = self._ssh_client.invoke_shell()
      ssh_channel.set_combine_stderr(True)
      self.child = self._spawn(ssh_channel, maxread=8192)
      timeout = max(1, self._connect_timeout)
      pattern = self.child.expect([self._success], timeout=timeout)
      if pattern == 0:
        self._MaybeFindPrompt()
    except pexpect.TIMEOUT:
      raise TimeoutError(timeout)
    except pexpect.EOF as e:
      raise ConnectionError(str(e))
    except paramiko.SSHException as e:
      msg = 'SSHException connecting to %r: %s' % (self._host, e)
      raise ConnectionError(msg)

    # Used by _Disconnect in ftos.py and ios.py.
    self.exit_list = self.child.compile_pattern_list(pexpect.EOF)
    return None


class HpSshFilterConnection(ParamikoSshConnection):
  """Creates an SSH connection to an HP Switch with terminal escape filtering.

  This filters terminal escape sequences seen on the Hewlett-Packard ProCurve
  ethernet switches.
  """

  def __init__(self, host, username, password=None, success=None,
               timeout=None, find_prompt=False, ssh_keys=None,
               enable_password=None, ssh_client=None, find_prompt_prefix=None):
    super(HpSshFilterConnection, self).__init__(
        host, username, password, success, timeout, find_prompt,
        ssh_keys=ssh_keys, enable_password=enable_password,
        ssh_client=ssh_client, find_prompt_prefix=find_prompt_prefix)
    self._spawn = HpSshSpawn

  def _MaybeFindPrompt(self):
    """Perform real login and then enable if we have an enable password."""
    # We always run this for HP, no matter the state of self._find_prompt.
    self._prompt = r'(?:^|\n|\r)([A-Za-z0-9\._-]+)(?:>|#) '
    # Shake out the prompt.  We may be facing a Password prompt or
    # a 'Press any key to continue' prompt.
    self.child.send('\r')

    # Only send the password once.
    password_sent = False
    try:
      # Login.
      while True:
        logging.vlog(3, 'Expecting prompt %r', self._prompt)
        compiled_regexes = self.child.compile_pattern_list(
            [self._prompt, r'Press any key to continue',
             'Password:', 'Invalid password',
             'Unable to verify password'])
        i = self.child.expect(compiled_regexes, timeout=10)
        if i == 0:
          re_str = (re.escape(self.child.match.group(1)) +
                    r'(?:>|#) ')
          logging.vlog(3, 'Prompt set to %r', re_str)
          self.re_prompt = re.compile(re_str)
          break
        elif i == 1:
          logging.vlog(3, 'Pressing any key (space)')
          self.child.send(' ')
        elif i == 2 and not password_sent:
          # Send the password only once.
          try:
            self.child.sendline(self._password)
            logging.vlog(3, 'Sent user password (again) to %r', self._host)
            password_sent = True
          except (pexpect.TIMEOUT, pexpect.EOF) as e:
            self._ssh_client = None
            raise ConnectionError(str(e))
        elif i <= 3 and i < 5:
          logging.error('CONNECT_ERROR Incorrect user password on %r',
                        self._host)

        # Sleep momentarily before expecting again to break buffer swap races.
        time.sleep(0.05)

      # Enable.
      password_sent = False
      logging.vlog(3, 'Enabling for HP on %r', self._host)
      self.child.sendline('enable')
      while True:
        i = self.child.expect([self._prompt, 'Password:',
                               'Invalid password',
                               'Unable to verify password'], timeout=10)
        if i == 0:
          # Found the prompt, we're enabled.
          break
        elif i == 1 and not password_sent:
          if self._enable_password is not None:
            self.child.sendline(self._enable_password)
            logging.vlog(3, 'Sent enable password to %r', self._host)
          else:
            self.child.sendline(self._password)
            logging.vlog(3, 'Sent user password to %r', self._host)
          password_sent = True
        elif i <= 3 and i < 5:
          logging.error('CONNECT_ERROR Incorrect user password on %r',
                        self._host)
          # Sleep momentarily before expecting again to break buffer swap races.
          time.sleep(0.05)
    except (pexpect.TIMEOUT, pexpect.EOF) as e:
      self._ssh_client = None
      raise ConnectionError(str(e))


class ScpPutConnection(Connection):
  """Copies a file via SCP (RCP over SSH)."""

  def __init__(self, host, username, password=None):
    """Initializer.

    Args:
      host: As per parent.
      username: As per parent.
      password: As per parent.
    """
    super(ScpPutConnection, self).__init__(host, username, password)
    self._ssh_client = sshclient.Connect(hostname=self._host,
                                         username=self._username,
                                         password=self._password)
    self.transport = self._ssh_client.get_transport()

  def Copy(self, source_data, destination_file):
    """Handles the SCP file copy.

    Args:
      source_data: The source data to copy as a string
      destination_file: The file on the remote device

    Raises:
      ScpError: There was an error copying the file.
    """
    try:
      sshclient.ScpPut(self.transport, source_data, destination_file,
                       self._connect_timeout)
    except sshclient.ScpError as e:
      raise ScpError('SCP put failed: %s: %s' % (e.__class__.__name__, e))

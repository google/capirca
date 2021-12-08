# Copyright 2011 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""Common library for network ports and protocol handling."""



class Error(Exception):
  """Base error class."""


class BadPortValue(Error):
  """Invalid port format."""


class BadPortRange(Error):
  """Out of bounds port range."""


class InvalidRange(Error):
  """Range is not valid (eg, single port)."""


class NotSinglePort(Error):
  """Port range defined instead of a single port."""


class PPP:
  """PPP: [P]ort [P]rotocol [P]airs.

  Make port/protocol pairs an object for easy comparisons
  """

  def __init__(self, service):
    """Init for PPP object.

    Args:
      service: A port/protocol pair as str (eg: '80/tcp', '22-23/tcp') or
               a nested service name (eg: 'SSH')
    """
    # remove comments (if any)
    self.service = service.split('#')[0].strip()
    if '/' in self.service:
      self.port = self.service.split('/')[0]
      self.protocol = self.service.split('/')[1]
      self.nested = False
    else:
      # for nested services
      self.nested = True
      self.port = None
      self.protocol = None

  @property
  def is_range(self):
    if self.port:
      return '-' in self.port
    else:
      return False

  @property
  def is_single_port(self):
    if self.port:
      return '-' not in self.port
    else:
      return False

  @property
  def start(self):
    # return the first port in the range as int
    if '-' in self.port:
      self._start = int(self.port.split('-')[0])
    else:
      raise InvalidRange('%s is not a valid port range' % self.port)
    return self._start

  @property
  def end(self):
    # return the last port in the range as int
    if '-' in self.port:
      self._end = int(self.port.split('-')[1])
    else:
      raise InvalidRange('%s is not a valid port range' % self.port)
    return self._end

  def __contains__(self, other):
    # determine if a single-port object is within another objects' range
    try:
      return ((int(self.start) <= int(other.port) <= int(self.end)) and
              self.protocol == other.protocol)
    except:
      raise InvalidRange('%s must be a range' % self.port)

  def __lt__(self, other):
    if self.is_single_port:
      try:
        return int(self.port) < int(other.port)
      except:
        return False
    else:
      raise NotSinglePort('Comparisons cannot be performed on port ranges')

  def __gt__(self, other):
    if self.is_single_port:
      try:
        return int(self.port) > int(other.port)
      except:
        return False
    else:
      raise NotSinglePort('Comparisons cannot be performed on port ranges')

  def __le__(self, other):
    if self.is_single_port:
      try:
        return int(self.port) <= int(other.port)
      except:
        return False
    else:
      raise NotSinglePort('Comparisons cannot be performed on port ranges')

  def __ge__(self, other):
    if self.is_single_port:
      try:
        return int(self.port) >= int(other.port)
      except:
        return False
    else:
      raise NotSinglePort('Comparisons cannot be performed on port ranges')

  def __eq__(self, other):
    if self.is_single_port:
      try:
        return (int(self.port) == int(other.port) and
                self.protocol == other.protocol)
      except:
        return False
    else:
      raise NotSinglePort('Comparisons cannot be performed on port ranges')


def Port(port):
  """Sanitize a port value.

  Args:
    port: a port value

  Returns:
    port: a port value

  Raises:
    BadPortValue: port is not valid integer or string
    BadPortRange: port is outside valid range
  """
  pval = -1
  try:
    pval = int(port)
  except ValueError:
    raise BadPortValue('port %s is not valid.' % port)
  if pval < 0 or pval > 65535:
    raise BadPortRange('port %s is out of range 0-65535.' % port)
  return pval

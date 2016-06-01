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

__author__ = 'watson@google.com (Tony Watson)'


class Error(Exception):
  """Base error class."""


class BadPortValue(Error):
  """Invalid port format."""


class BadPortRange(Error):
  """Invalid port range."""


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

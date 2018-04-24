# Copyright 2015 Google Inc. All Rights Reserved.
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

"""Arista generator."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from capirca.lib import cisco


class Error(Exception):
  """Base error class."""


class UnsupportedEosAccessListError(Error):
  """When a filter type is not supported in an EOS policy target."""


class Arista(cisco.Cisco):
  """An Arista policy object.

  EOS devices differ slightly from Cisco, omitting the extended argument to
  ACLs for example. There are other items such as 'tracked' we may want to add
  in the future.
  """

  _PLATFORM = 'arista'
  SUFFIX = '.eacl'
  # Protocols should be emitted as they were in the policy (names).
  _PROTO_INT = False

  # Arista omits the "extended" access-list argument.
  def _AppendTargetByFilterType(self, filter_name, filter_type):
    """Takes in the filter name and type and appends headers.

    Args:
      filter_name: Name of the current filter
      filter_type: Type of current filter

    Returns:
      list of strings

    Raises:
      UnsupportedEosAccessListError: When unknown filter type is used.
    """
    target = []
    if filter_type == 'standard':
      if filter_name.isdigit():
        target.append('no access-list %s' % filter_name)
      else:
        target.append('no ip access-list standard %s' % filter_name)
        target.append('ip access-list standard %s' % filter_name)
    elif filter_type == 'extended':
      target.append('no ip access-list %s' % filter_name)
      target.append('ip access-list %s' % filter_name)
    elif filter_type == 'object-group':
      target.append('no ip access-list %s' % filter_name)
      target.append('ip access-list %s' % filter_name)
    elif filter_type == 'inet6':
      target.append('no ipv6 access-list %s' % filter_name)
      target.append('ipv6 access-list %s' % filter_name)
    else:
      raise UnsupportedEosAccessListError(
          'access list type %s not supported by %s' % (
              filter_type, self._PLATFORM))
    return target

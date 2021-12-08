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

"""Brocade generator."""

from capirca.lib import cisco


class Brocade(cisco.Cisco):
  """A brocade policy object.

  Brocade devices do not like protocol numbers. Revert the protocol numbers to
  names just before emitting acl lines to minimize difference from Cisco logic.
  """

  _PLATFORM = 'brocade'
  SUFFIX = '.bacl'
  # Protocols should be emitted as they were in the policy (names).
  _PROTO_INT = False
  _TERM_REMARK = False

#!/usr/bin/python2.4
#
# Copyright 2011 Google Inc. All Rights Reserved.
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

"""Speedway iptables generator.

   This is a subclass of Iptables library.  The primary difference is
   that this library produced 'iptable-restore' compatible output."""

__author__ = 'watson@google.com (Tony Watson)'

import iptables


class Term(iptables.Term):
  """Generate Iptables policy terms."""
  _PLATFORM = 'speedway'
  _PREJUMP_FORMAT = None
  _POSTJUMP_FORMAT = '-A %s -j %s'


class Speedway(iptables.Iptables):
  """Generates filters and terms from provided policy object."""

  _PLATFORM = 'speedway'
  _DEFAULT_PROTOCOL = 'all'
  _SUFFIX = '.ipt'

  _RENDER_PREFIX = '*filter'
  _RENDER_SUFFIX = 'COMMIT\n'
  _DEFAULTACTION_FORMAT = ':%s %s'

  _TERM = Term

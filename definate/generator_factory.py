#!/usr/bin/python
#
# Copyright 2012 Google Inc. All Rights Reserved.
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

"""Functionality to allow easily retrieving the right definition generator."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

__author__ = 'msu@google.com (Martin Suess)'


import dns_generator


class Error(Exception):
  """Base error class."""


class GeneratorIdentificationError(Error):
  """Exception to use when GeneratorFactory fails to identify the Generator."""


class GeneratorFactory(object):
  """Functionality to get a definition generator easily based on its name."""

  def __init__(self):
    """Initializer."""
    self._generators = {
        'DnsGenerator': dns_generator.DnsGenerator,
        }

  def GetGenerator(self, identifier):
    """Returns a specific generator instance based on the identifier.

    Args:
      identifier: String identifier for the generator to get.

    Raises:
      GeneratorIdentificationError: If the generator cannot be identified.

    Returns:
      Generator instance based on the identifier passed in.
    """
    if identifier not in self._generators:
      raise GeneratorIdentificationError(
          'Generator \'%s\' could not be identified.' % identifier)
    return self._generators[identifier]()

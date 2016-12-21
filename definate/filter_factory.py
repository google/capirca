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

"""Functionality to allow easily retrieving certain filter objects."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

__author__ = 'msu@google.com (Martin Suess)'


import definition_filter
import file_filter

DEFINITION_FILTER = 1
FILE_FILTER = 2
GLOBAL_FILTER = 3

PRE_FILTERS = 'PreFilters'
POST_FILTERS = 'PostFilters'


class Error(Exception):
  """Base error class."""


class FilterIdentificationError(Error):
  """Exception to use when FilterFactory fails to identify the Filter."""


class FilterFactory(object):
  """Functionality to get a filter object easily based on its name.

  This class can be initialized and the GetFilter() method allows retrieving a
  specific filter based on the name of the filter and the scope (global, file
  and definition).
  """

  def __init__(self):
    """Initializer."""
    self._filters = {
        DEFINITION_FILTER: {
            'PostFilters': {
                'SortFilter': definition_filter.SortFilter,
                'AlignFilter': definition_filter.AlignFilter,
                },
            },
        FILE_FILTER: {
            'PostFilters': {
                'PrintFilter': file_filter.PrintFilter,
                'WriteFileFilter': file_filter.WriteFileFilter,
                },
            },
        GLOBAL_FILTER: {
            'PreFilters': {
                },
            'PostFilters': {
                },
            },
        }

  def GetFilter(self, scope, identifier, sequence):
    """Returns a specific filter instance based on the identifier.

    Args:
      scope: Type of filter to be returned. Valid types are listed as globals
        in the beginning of this module.
      identifier: String identifier for the filter to get.
        sequence: String identifier for the sequence information to determine
        when the filter should be applied. Valid values:
          - 'PreFilters': Filters that are applied before processing the data
              (e.g. before the definition is created).
          - 'PostFilters': Filters that are applied after processing the data
              (e.g. after the definition has been created).

    Raises:
      FilterIdentificationError: If the filter cannot be identified.

    Returns:
      Filter instance based on the identifier passed in.
    """
    if scope not in self._filters:
      raise FilterIdentificationError(
          'Filter scope \'%d\' could not be found in filters.' % scope)
    if sequence not in self._filters[scope]:
      raise FilterIdentificationError(
          'Filter sequence \'%s\' is not applicable to scope \'%d\'.' % (
              sequence, scope))
    filters = self._filters[scope][sequence]
    if identifier not in filters:
      raise FilterIdentificationError(
          'Filter \'%s\' could not be identified. Wrong scope (%d) or sequence'
          ' (%s)?' % (identifier, scope, sequence))
    return filters[identifier]()

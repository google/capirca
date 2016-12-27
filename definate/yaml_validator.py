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

"""Tools to allow the verification of the YAML configuration for Definate."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

__author__ = 'msu@google.com (Martin Suess)'


class Error(Exception):
  """Base error class."""


class DefinateConfigError(Error):
  """Exception to use when Definate fails reading the configuration."""


class YamlValidator(object):
  """Class to verify the sanity of a YAML configuration."""

  def CheckConfigurationItem(self, dictionary, item, typ=None):
    """Checks for the presence of an item in a dictionary.

    Args:
      dictionary: Configuration part that should be checked.
      item: Name of the key to check as string.
      typ: Type of the value to check. Default is to not check the type.

    Raises:
      DefinateConfigError: The configuration is not sane.
    """
    if not dictionary or item not in dictionary:
      raise DefinateConfigError('"%s" is not defined in config: %s'
                                % (item, dictionary))
    if typ and type(dictionary[item]) is not typ:
      raise DefinateConfigError('Type of "%s" is %s, expected %s.' %
                                (item, str(type(dictionary[item])), str(typ)))

  def CheckConfiguration(self, config, structure, max_recursion_depth=30):
    """Recursively checks the sanity and structure of the configuration.

    This method checks the sanity of the configuration structure for Definate
    and raises a DefinateConfigError if the configuration is not sane.

    Args:
      config: Dictionary generated from the YAML configuration file which should
        be checked.
      structure: Structure of the configuration against which should be checked.
      max_recursion_depth: Defines the maximum amount of recursion cycles before
        checking is aborted. Default is 30.

    Raises:
      DefinateConfigError: The configuration is not sane.
    """
    max_depth = max_recursion_depth - 1
    if max_depth <= 0:
      raise DefinateConfigError('Maximum recursion depth reached. Please check '
                                'configuration manually.')
    if type(structure) in [dict, list]:
      for item in structure:
        value = item
        if type(structure) is dict:
          value = structure[item]

        self.CheckConfigurationItem(config, item, typ=type(value))
        if type(value) is dict:
          self.CheckConfiguration(config[item], value, max_depth)
        elif type(value) is list:
          for (i, list_value) in enumerate(value):
            self.CheckConfiguration(config[item][i], list_value, max_depth)
    elif type(structure) is type(config):
      return
    else:
      raise DefinateConfigError('Type of "%s" is %s, expected %s.' % (
          config, str(type(config)), str(structure)))

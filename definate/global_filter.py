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

"""Module that holds all global-level filter classes of Definate."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

__author__ = 'msu@google.com (Martin Suess)'


import yaml_validator


class Error(Exception):
  """Base error class."""


class Container(object):
  """Container class to hold all information to be passed between filters."""

  def __init__(self, absolute_paths=None, relative_paths=None):
    """Initializer.

    Args:
      absolute_paths: Optional list of strings to specify the full path of the
        generated files
        (e.g. ['//depot/def/AUTOGEN1.net', '/tmp/AUTOGEN2.net']).
      relative_paths: Optional list of strings to specify the paths of the
        generated files relative to the location of the definition directory
        (e.g. ['AUTOGEN1.net']).
    """
    self.absolute_paths = absolute_paths if absolute_paths else []
    self.relative_paths = relative_paths if relative_paths else []
    self.changelist = ''


class GlobalFilter(object):
  """Abstract class defining the interface for the filter chain objects."""

  def __init__(self):
    """Initializer."""
    self._yaml_validator = yaml_validator.YamlValidator()

  def Filter(self, container, args):
    """Interface to filter or modify data passed into it.

    Args:
      container: Container object which holds all global information.
        See Container class for details.
      args: Dictionary of arguments depending on the actual filter in use.

    Raises:
      NotImplementedError: In any case since this is not implemented an needs
        to be defined by subclasses.
    """
    raise NotImplementedError(
        'This is an interface only. Implemented by subclasses.')

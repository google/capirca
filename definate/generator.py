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

"""Module holding the abstract definition generator class."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

__author__ = 'msu@google.com (Martin Suess)'


import yaml_validator


class Error(Exception):
  """Base error class."""


class GeneratorError(Error):
  """Base Generator error class to inherit from in specific generators."""


class Generator(object):
  """Abstract class defining the interface for the definition generation."""

  def __init__(self):
    """Initializer."""
    self._yaml_validator = yaml_validator.YamlValidator()

  def GenerateDefinition(self, config, global_config):
    """Interface to generate definitions based on a configuration passed in.

    Classes inheriting from Generator should implement this interface by parsing
    the configuration and generating a network definition based on it.
    For reference, have a look at the already implemented classes.

    Args:
      config: Configuration necessary to generate one full definition.
      global_config: Global configuration section.

    Raises:
      NotImplementedError: In any case since this is not implemented and needs
        to be defined by sublcasses.
    """
    raise NotImplementedError(
        'This is an interface only. Implemented by subclasses.')

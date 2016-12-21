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

"""Generates network definitions for use with Capirca.

Definate is a framework to generate definitions for the automatic network policy
generation framework. The definitions are generated based on a configuration
file.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

__author__ = 'msu@google.com (Martin Suess)'

import logging
from optparse import OptionParser
import os
import yaml

from definate import definition_filter
from definate import file_filter
from definate import filter_factory
from definate import generator_factory
from definate import global_filter
from definate import yaml_validator


_parser = OptionParser()
_parser.add_option('-c', '--config', dest='configuration',
                   help='configuration file',
                   default='./definate/definate.yaml')
_parser.add_option('-d', '--def', dest='definitions',
                   help='definitions directory', default='./def')
_parser.add_option('--debug', help='enable debug-level logging', dest='debug')
(FLAGS, args) = _parser.parse_args()


class Error(Exception):
  """Base error class."""


class DefinateGenerationError(Error):
  """Exception to use when Definate fails generating output."""


class Definate(object):
  """Generates the network definition files."""

  def __init__(self):
    """Initializer."""
    self._generator_factory = generator_factory.GeneratorFactory()
    self._filter_factory = filter_factory.FilterFactory()
    self._yaml_validator = yaml_validator.YamlValidator()

  def _ReadConfiguration(self, conf_path):
    """Reads the configuration from a YAML file.

    Args:
      conf_path: String representing the path to the configuration file.

    Raises:
      DefinateConfigError: The configuration cannot be read.

    Returns:
      YAML generated configuration structure (lists and dictionaries containing
      configuration values).
    """
    try:
      config_file = file(conf_path, 'r')
    except IOError as e:
      raise yaml_validator.DefinateConfigError('Unable to open config: %s' % e)
    config = yaml.safe_load(config_file)
    config_file.close()
    return config

  def GenerateDefinitions(self, config_path, def_path):
    """Generate all network definition files based on the config passed in.

    Args:
      config_path: Full path to the YAML configuration file as a string.
        See YAML configuration file for reference: README
      def_path: Full path to the directory where the network definitions are
      stored as string.

    Raises:
      DefinateConfigError: The configuration that has been passed in is not
        sane.
    """
    yaml_structure = {
        'global': {},
        'files': [{
            'path': 'str',
            'generators': [{
                'name': 'str',
                'definitions': [{
                    'name': 'str',
                    'networks': [],
                    }],
                }],
            }],
        }

    config = self._ReadConfiguration(config_path)
    self._yaml_validator.CheckConfiguration(config, yaml_structure)
    logging.info('Configuration check: Done. Global config appears to be sane.')

    additional_args = {'def_path': def_path}

    global_config = config['global']

    global_container = global_filter.Container()
    # TODO(msu): Maybe add sanity check filter which is always run?
    global_container = self._RunFilter(
        filter_factory.GLOBAL_FILTER, filter_factory.PRE_FILTERS,
        global_config.get('pre_filters', []),
        global_container, filterargs=additional_args)

    for file_definition in config['files']:
      relative_path = file_definition['path']
      file_path = os.path.join(def_path, relative_path)
      logging.info('Generating file: %s', file_path)

      file_header = file_definition.get('file_header', [])
      if file_header:
        file_header = ['# %s' % line for line in file_header]
        file_header.append('\n')
      file_container = file_filter.Container(
          lines=file_header, absolute_path=file_path,
          relative_path=relative_path)

      file_container = self._RunFilter(
          filter_factory.FILE_FILTER, filter_factory.PRE_FILTERS,
          global_config.get('per_file_pre_filters', []),
          file_container, filterargs=additional_args)
      file_container = self._RunFilter(
          filter_factory.FILE_FILTER, filter_factory.PRE_FILTERS,
          file_definition.get('pre_filters', []),
          file_container, filterargs=additional_args)

      file_container = self._GenerateFile(
          file_definition['generators'], global_config, file_container)

      global_container.absolute_paths.append(file_path)
      global_container.relative_paths.append(relative_path)

      # TODO(msu): Maybe add some sanity check filter which is always run?
      file_container = self._RunFilter(
          filter_factory.FILE_FILTER, filter_factory.POST_FILTERS,
          file_definition.get('post_filters', []),
          file_container, filterargs=additional_args)
      file_container = self._RunFilter(
          filter_factory.FILE_FILTER, filter_factory.POST_FILTERS,
          global_config.get('per_file_post_filters', []),
          file_container, filterargs=additional_args)

    # TODO(msu): Maybe add some sanity check filter which is always run?
    global_container = self._RunFilter(
        filter_factory.GLOBAL_FILTER, filter_factory.POST_FILTERS,
        global_config.get('post_filters', []),
        global_container, filterargs=additional_args)

  def _GenerateFile(self, generators, global_config, file_container):
    """Generate one network definition file.

    Args:
      generators: Configuration based on which the file is generated.
      global_config: Global section of the configuration.
      file_container: Dictionary representing the container used to hold all
        information for one definition file.

    Returns:
      Container dictionary as defined in file_filter module.

    Raises:
      DefinateGenerationError: In case one of the generated definition does not
        contain any nodes.
      DefinateConfigError: In case the configuration is not well formed.
    """
    for generator_config in generators:
      generator = self._generator_factory.GetGenerator(
          generator_config['name'])
      logging.info('Running generator \"%s\" now.', generator_config['name'])

      for definition in generator_config['definitions']:
        def_header = definition.get('header', [])
        if def_header:
          def_header = ['# %s' % line for line in def_header]
        def_container = definition_filter.Container(
            header=def_header, name=definition.get('name'))
        logging.info('Generating definition: %s', definition.get('name'))

        def_container = self._RunFilter(
            filter_factory.DEFINITION_FILTER, filter_factory.PRE_FILTERS,
            global_config.get('per_definition_pre_filters', []),
            def_container)
        def_container = self._RunFilter(
            filter_factory.DEFINITION_FILTER, filter_factory.PRE_FILTERS,
            definition.get('pre_filters', []),
            def_container)

        def_container.entries_and_comments = generator.GenerateDefinition(
            definition.get('networks', []), global_config)

        if not def_container.entries_and_comments:
          raise DefinateGenerationError(
              'Generator returned no nodes for this definition: %s' % (
                  definition.get('name')))

        # TODO(msu): Maybe add sanity check filter which is always run?
        def_container = self._RunFilter(
            filter_factory.DEFINITION_FILTER, filter_factory.POST_FILTERS,
            definition.get('post_filters', []),
            def_container)
        def_container = self._RunFilter(
            filter_factory.DEFINITION_FILTER, filter_factory.POST_FILTERS,
            global_config.get('per_definition_post_filters', []),
            def_container)

        if not def_container.string_representation:
          # TODO(msu): Define what should happen if no/wrong filters have been
          # applied and no output is generated. Discard? Warn? Write warning to
          # file?
          pass
        else:
          file_container.lines.extend(def_container.header)
          file_container.lines.append(def_container.string_representation)
          file_container.lines.append('')

    return file_container

  def _RunFilter(self, filter_type, sequence, filter_config, container,
                 filterargs=None):
    """Checks filter config and runs filters specified depending on type.

    Args:
      filter_type: Integer defining the filter type to use. Valid values are
        specified in the filter_factory module.
      sequence: String identifier for when the filter is run. Valid values are
        specified in the filter_factory module.
      filter_config: Configuration structure as defined in the YAML
        configuration.
      container: Container dictionary as a bucket for all necessary information
        to pass from filter to filter.
      filterargs: Optional argument dictionary that is passed to a filter. Note
        that these args update (and potentially overwrite) previously configured
        arguments from the YAML configuration.

    Returns:
      Container dictionary that has been passed in.

    Raises:
      DefinateConfigError: In case the configuration is not well formed.
    """
    if not filter_config:
      logging.debug('Filter config has not been specified.')
      return container

    if not filterargs:
      filterargs = {}

    for filter_def in filter_config:
      self._yaml_validator.CheckConfigurationItem(filter_def, 'name')
      filter_name = filter_def['name']
      filter_args = filter_def.get('args', {})
      filter_args.update(filterargs)
      fltr = self._filter_factory.GetFilter(
          filter_type, filter_name, sequence)
      logging.debug('Running filter \"%s\".', filter_name)
      container = fltr.Filter(container, filter_args)

    return container


def main():
  if FLAGS.debug:
    logging.basicConfig(level=logging.DEBUG)
  definate = Definate()
  definate.GenerateDefinitions(FLAGS.configuration,
                               FLAGS.definitions)

if __name__ == '__main__':
  main()

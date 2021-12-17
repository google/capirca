"""A module to handle merging file configurations with CLI configs for Capirca."""

import yaml

defaults = {
    'base_directory': './policies',
    'definitions_directory': './def',
    'policy_file': None,
    'output_directory': './',
    'optimize': False,
    'recursive': True,
    'debug': False,
    'verbose': False,
    'ignore_directories': ['DEPRECATED', 'def'],
    'max_renderers': 10,
    'shade_check': False,
    'exp_info': 2
}


def yaml_loader(filename):
  with open(filename, 'r') as f:
    try:
      data = yaml.safe_load(f)
    except AttributeError:
      data = yaml.safe_load(f)

  return data


def flags_to_dict(absl_flags):
  base = {
      'base_directory': absl_flags.base_directory,
      'definitions_directory': absl_flags.definitions_directory,
      'policy_file': absl_flags.policy_file,
      'output_directory': absl_flags.output_directory,
      'optimize': absl_flags.optimize,
      'recursive': absl_flags.recursive,
      'debug': absl_flags.debug,
      'verbose': absl_flags.verbose,
      'ignore_directories': absl_flags.ignore_directories,
      'max_renderers': absl_flags.max_renderers,
      'shade_check': absl_flags.shade_check,
      'exp_info': absl_flags.exp_info,
  }

  return {
      flag: base[flag] for flag in filter(lambda f: base[f] is not None, base)
  }


def merge_files(*files):
  result = {}

  for item in files:
    data = yaml_loader(item)
    result.update(data)

  return {
      flag: result[flag]
      for flag in filter(lambda f: result[f] is not None, result)
  }


def generate_configs(absl_flags):
  cli_configs = flags_to_dict(absl_flags)
  if absl_flags.config_file:
    file_configs = merge_files(*absl_flags.config_file)
  else:
    file_configs = {}

  result = defaults.copy()
  result.update(cli_configs)
  result.update(file_configs)

  return result

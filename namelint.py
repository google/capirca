#!/usr/bin/env python
# Copyright 2008 Google Inc. All Rights Reserved.
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

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import os
import argparse

from lib.linters import build_linters, severity as sev
from lib.naming import Naming

__author__ = 'mikeelkin2@fb.com (Mike Elkin)'


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('file', nargs='+', type=str,
                      metavar='SOMETHING.net',
                      help="NETWORK/SERVICE file to run against")
  parser.add_argument('-c', '--config',
                      help="YAML configuration file (optional)")
  parser.add_argument('-o', '--output', choices=['pretty', 'plain', 'json'],
                      default='pretty', help="Output format")
  ns = parser.parse_args()

  errors, linters = build_linters(ns.config)

  for filename in ns.file:
    fn = os.path.abspath(os.path.expanduser(filename))
    errors.filename = filename
    if filename.endswith('.svc'):
      svctype = 'services'
    elif filename.endswith('.net'):
      svctype = 'networks'
    else:
      errors.add(sev.ERROR, 'Unknown extension: %s' % filename)
      continue

    try:
      processed = Naming(naming_dir='/', naming_file=fn, naming_type=svctype)
    except Exception as e:
      errors.add(sev.ERROR, '%s had exception: %s' % (filename, e))
      continue

    for linter in linters:
      linter.lint_naming(processed)

  if ns.output == 'pretty':
    errors.pprint()
  elif ns.output == 'plain':
    errors.plain()
  elif ns.output == 'json':
    errors.json()

if __name__ == '__main__':
  main()

#!/usr/bin/env python
#
# Copyright 2009 Google Inc.
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


import os
from setuptools import setup, find_packages

def find_data_files(source):
  result = []
  for directory, _, files in os.walk(source):
    files = [os.path.join(directory, x) for x in files]
    result.append((directory, files))

  return result
data_files = (["aclcheck_cmdline.py", "aclgen.py", "definate.py"] +
              find_data_files("def") +
              find_data_files("definate") +
              find_data_files("lib") +
              find_data_files("policies") +
              find_data_files("tests") +
              find_data_files("third_party") +
              find_data_files("tools"))

setup(
    name='capirca',
    version="1.118",
    description='Capirca',
    license='Apache License, Version 2.0',
    url='https://github.com/google/capirca/',
    maintainer='Rob Ankeny',
    maintainer_email='robankeny at google dot com',
    packages=find_packages(),
    zip_safe=False,
    classifiers=[
                 'Topic :: Security',
                 'Topic :: System :: Networking :: Firewalls',
                ],
    include_package_data=True,
    data_files=data_files,
    install_requires=['python-gflags', 'ply', 'ipaddr', 'mock'])

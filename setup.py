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

setup(
    name='capirca',
    version='1.121',
    description='Capirca',
    license='Apache License, Version 2.0',
    url='https://github.com/google/capirca/',
    maintainer='Rob Ankeny',
    maintainer_email='robankeny@google.com',
    packages=find_packages(exclude=["tests*"]),
    zip_safe=False,
    entry_points={
        'console_scripts': ['aclgen = capirca.aclgen:entry_point'],
    },
    classifiers=[
                 'Topic :: Security',
                 'Topic :: System :: Networking :: Firewalls',
                ],
    install_requires=['absl-py', 'ply', 'ipaddr', 'mock', 'six']
)

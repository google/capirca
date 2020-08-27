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


from setuptools import find_packages
from setuptools import setup

with open('VERSION') as f:
  version = f.read()

with open('README.md') as f:
  long_description = f.read()

setup(
    name='capirca',
    version=version,
    description='Capirca',
    long_description=long_description,
    long_description_content_type='text/markdown',
    license='Apache License, Version 2.0',
    url='https://github.com/google/capirca/',
    maintainer='Rob Ankeny',
    maintainer_email='robankeny@google.com',
    packages=find_packages(exclude=['tests*']),
    zip_safe=False,
    entry_points={
        'console_scripts': ['aclgen = capirca.aclgen:entry_point'],
    },
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Topic :: Security',
        'Topic :: System :: Networking :: Firewalls',
    ],
    install_requires=[
        'absl-py',
        'ply',
        'ipaddress>=1.0.22',
        'mock',
        'six',
        'PyYAML',
    ]
)

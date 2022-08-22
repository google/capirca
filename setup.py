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
"""capirca installation module."""

from os import path
import setuptools

root_dir = path.abspath(path.dirname(__file__))

with open(path.join(root_dir, 'VERSION'), encoding='utf-8') as f:
  version = f.readline().strip()

with open(path.join(root_dir, 'README.md'), encoding='utf-8') as f:
  long_description = f.read()

setuptools.setup(
    name='capirca',
    version=version,
    description='Capirca',
    long_description=long_description,
    long_description_content_type='text/markdown',
    license='Apache License, Version 2.0',
    url='https://github.com/google/capirca/',
    maintainer='Capirca Team',
    maintainer_email='capirca-dev@google.com',
    packages=['capirca', 'capirca.lib', 'capirca.utils'],
    zip_safe=False,
    entry_points={
        'console_scripts': ['aclgen = capirca.aclgen:EntryPoint'],
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
        'mock',
        'six',
        'PyYAML',
    ],
    python_requires='>=3.6',
)

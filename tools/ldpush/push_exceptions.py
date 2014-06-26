#!/usr/bin/python
#
# Copyright 2013 Google Inc.
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
"""Exceptions raised by the push librarires."""


class Error(Exception):
  pass


class ConnectError(Error):
  """Indicates a connection could not be established."""


class CmdError(Error):
  """An Error that occurred while executing a Cmd method."""


class GetConfigError(Error):
  """An Error that occurred inside GetConfig."""


class EmptyConfigError(GetConfigError):
  """An empty configuration was produced by the GetConfig command."""


class SetConfigError(Error):
  """An Error that occurred inside SetConfig."""


class SetConfigCanaryingError(Error):
  """The request to canary the configuration failed (probably not supported)."""


class SetConfigSyntaxError(Error):
  """The device reported a configuration syntax error during SetConfig."""


class DisconnectError(Error):
  """An error occurred during device Disconnect."""


class AuthenticationError(Error):
  """The authentication details for the connection failed to gain access."""

#!/bin/bash
# Copyright 2016 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Cannot disable R0801, seems this is a known issue from searching online.
find . -name "*.py" | \
xargs pylint --rcfile tools/pylintrc --msg-template='{msg_id}:{line:4} {obj}: {msg}[{symbol}]' |\
sed -e ':a;N;$!ba;s/R0801.*duplicate-code]//g' | tee ./tools/new_lint_errors.txt;

if ! cmp ./tools/current_lint_errors.txt ./tools/new_lint_errors.txt >/dev/null 2>&1
then
    echo "[ERROR] Looks like some errors came up.";
    echo "[ERROR] Please check that you are not adding new errors."
    echo "[ERROR] diff tools/current_lint_errors.txt tools/new_lint_errors.txt"
    exit 1
else
    echo "[OK] The codebase passes the linter tests!";
fi

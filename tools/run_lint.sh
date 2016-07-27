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
find . -name "*.py" | sort |\
xargs pylint --rcfile tools/pylintrc --msg-template='{msg_id}:{line:4} {obj}: {msg}[{symbol}]' > ./tools/new_lint_errors.txt

# Cannot disable the following errors, seems this is a known issue from searching online.
sed -i ':a;N;$!ba;s/R0801.*duplicate-code]//g' ./tools/new_lint_errors.txt
sed -i 's/R0904.*too-many-public-methods]//g' ./tools/new_lint_errors.txt
sed -i 's/R0912.*too-many-branches]//g' ./tools/new_lint_errors.txt
sed -i 's/R0914.*too-many-locals]//g' ./tools/new_lint_errors.txt
sed -i 's/R0915.*too-many-statements]//g' ./tools/new_lint_errors.txt
sed -i '/^\s*$/d' ./tools/new_lint_errors.txt
new_diff=$(diff -u tools/current_lint_errors.txt tools/new_lint_errors.txt | grep -E "^\+[^+]")

if [ "$new_diff" == "" ]
then
    echo "[OK] The codebase passes the linter tests!";
else
    echo "[ERROR] There are additional new lint errors present in your changes."
    echo "$new_diff"
    exit 1
fi

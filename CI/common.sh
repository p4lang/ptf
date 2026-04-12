# Copyright 2023 Antonin Bas
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
#
# SPDX-License-Identifier: Apache-2.0

force=0
while [[ $# -gt 0 ]]; do
key="$1"
case $key in
    -f|--force)
    force=1
    ;;
    *)
            # unknown option
    ;;
esac
shift # past argument or value
done

function quit {
    if [ $force == 0 ]; then
        echo "skipping installation, you can force installation with '-f'"
        exit 0
    fi
}

function check_lib {
    ldconfig -p | grep $2 &> /dev/null
    if [ $? == 0 ]; then
        echo "$2 found"
        quit
    fi
    ldconfig -p | grep $1 &> /dev/null
    if [ $? == 0 ]; then
        echo "a version of $1 was found, but not $2"
        echo "you may experience issues when using a different version"
        quit
    fi
}

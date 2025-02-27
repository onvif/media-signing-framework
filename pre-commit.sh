#!/bin/sh
# MIT License
#
# Copyright (c) 2025 ONVIF. All rights reserved.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to the following
# conditions:
#
# The above copyright notice and this permission notice (including the next paragraph)
# shall be included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
# CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR
# THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# Verify that the code passes static code check
#

if [ "$NO_VERIFY" ]; then
    echo 'pre-commit hook skipped' 1>&2
    exit 0
fi

echo "--Static code analysis--"
for file in `git diff-index --cached --name-only HEAD --diff-filter=ACMR| grep ".\/.*\.[c|h]$"` ; do
    # This makes sure to check against the revision in the index (and not the checked out version).

    clang-format -i $file
done
for diffile in `git diff --name-only --diff-filter=ACMR| grep ".\/.*\.[c|h]$"` ; do
echo "================================================================================"
echo " clang-format found problems with $file"
echo
echo " Run 'git diff' to see the diff and select 'git add -u' for accept or 'git checkout -- <file>' to decline."
    #git diff $diffile
    #git checkout -- $diffile
done
echo "--Static code analysis pass--"


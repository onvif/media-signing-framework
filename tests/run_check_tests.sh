#!/bin/bash
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

if [ -e ./run_check_tests.sh ]; then
    # Move up to top level before running meson
    cd ..
fi

# Remove any existing build directory
rm -rf build

echo ""
echo "=== Run with threaded signing plugin (should not do anything) ==="
echo ""

meson setup -Dbuildtype=debug -Dsigningplugin=threaded . build
ninja -C build test

echo ""
echo "=== Run check tests with threaded_unless_check_dep ==="
echo ""

meson setup -Dsigningplugin=threaded_unless_check_dep --reconfigure . build
ninja -C build test

echo ""
echo "=== Runs check tests with default (unthreaded) signing plugin ==="
echo ""

meson setup -Dsigningplugin=unthreaded --reconfigure . build
ninja -C build test

echo ""
echo "=== Run check tests with ONVIF_MEDIA_SIGNING_DEBUG debugprints ==="
echo ""

meson setup -Ddebugprints=true --reconfigure . build
ninja -C build test

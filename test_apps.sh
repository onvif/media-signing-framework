#!/bin/bash

# Set GST_PLUGIN_PATH so gStreamer can find local gst-elements
export GST_PLUGIN_PATH=$PWD/local_installs
VALIDATOR_PATH=$PWD/validator_installs
VALIDATOR=$VALIDATOR_PATH/bin/validator
SIGNER=$GST_PLUGIN_PATH/bin/signer
if [ $# -eq 0 ]
  then
    echo "No arguments supplied"
    PARSESEI="parsesei=false"
else
  PARSESEI=$1
fi
# Remove all old stuff
rm -rf build_signer
rm -rf build_validator
rm -rf $GST_PLUGIN_PATH
rm -rf $VALIDATOR_PATH
# rm validation_results.txt

echo ""
echo "=== Build the signer example app ==="
echo ""

# Build and install apps
meson setup -Dsigner=true -Dbuildtype=debug -D$PARSESEI --prefix $GST_PLUGIN_PATH . build_signer
meson install -C build_signer

echo ""
echo "=== Build the validator example app ==="
echo ""

meson setup -Dvalidator=true -Dbuildtype=debug -D$PARSESEI --prefix $VALIDATOR_PATH . build_validator
meson install -C build_validator

# Sign and validate test files
$VALIDATOR -c h264 examples/test-files/test_h264.mp4
cat validation_results.txt

$SIGNER -c h264 examples/test-files/test_h264.mp4
$VALIDATOR -C test -c h264 examples/test-files/signed_test_h264.mp4
cat validation_results.txt
rm examples/test-files/signed_test_h264.mp4

$VALIDATOR -b -c h265 examples/test-files/test_h265.mp4
cat validation_results.txt

$SIGNER -c h265 examples/test-files/test_h265.mp4
$VALIDATOR -b -C test -c h265 examples/test-files/signed_test_h265.mp4
cat validation_results.txt
rm examples/test-files/signed_test_h265.mp4

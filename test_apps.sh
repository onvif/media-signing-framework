#!/bin/bash

# Set GST_PLUGIN_PATH so GStreamer can find local gst-elements
export GST_PLUGIN_PATH=$PWD/local_installs
VALIDATOR_PATH=$PWD/validator_installs
VALIDATOR=$VALIDATOR_PATH/bin/validator
SIGNER=$GST_PLUGIN_PATH/bin/signer
TAMPERER=$VALIDATOR_PATH/bin/tamperByte
RESULTS_PATH=$PWD/app_test_results

validate()
{
  result_name=$1
  shift
  echo ""
  echo "=== Validate $result_name ==="
  "$VALIDATOR" "$@"
  cp validation_results.txt "$RESULTS_PATH/$result_name.txt"
  cat "$RESULTS_PATH/$result_name.txt"
}

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
rm -rf "$RESULTS_PATH"
mkdir -p "$RESULTS_PATH"

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
validate unsigned_h264 -c h264 examples/test-files/test_h264.mp4

$SIGNER -c h264 examples/test-files/test_h264.mp4
validate signed_h264 -C test -c h264 examples/test-files/signed_test_h264.mp4

$TAMPERER examples/test-files/signed_test_h264.mp4 examples/test-files/tampered_signed_test_h264.mp4
validate tampered_signed_h264 -C test -c h264 examples/test-files/tampered_signed_test_h264.mp4
rm examples/test-files/signed_test_h264.mp4
rm examples/test-files/tampered_signed_test_h264.mp4

validate unsigned_h265 -b -c h265 examples/test-files/test_h265.mp4

$SIGNER -c h265 examples/test-files/test_h265.mp4
validate signed_h265 -b -C test -c h265 examples/test-files/signed_test_h265.mp4

$TAMPERER examples/test-files/signed_test_h265.mp4 examples/test-files/tampered_signed_test_h265.mp4
validate tampered_signed_h265 -C test -c h265 examples/test-files/tampered_signed_test_h265.mp4
rm examples/test-files/signed_test_h265.mp4
rm examples/test-files/tampered_signed_test_h265.mp4

#!/bin/bash

# Set GST_PLUGIN_PATH so gStreamer can find local gst-elements
export GST_PLUGIN_PATH=$PWD/local_installs
VALIDATOR_PATH=$PWD/validator_installs
VALIDATOR=$VALIDATOR_PATH/bin/validator
SIGNER=$GST_PLUGIN_PATH/bin/signer
# Remove all old stuff
rm -rf build_lib_for_signing
rm -rf build_lib_for_validation
rm -rf build_signer
rm -rf build_validator
rm -rf $GST_PLUGIN_PATH
rm -rf $VALIDATOR_PATH
rm validation_results.txt
rm signed_test_h264.mp4
rm signed_test_h265.mp4
rm test_h264.mp4
rm test_h265.mp4
rm private_ecdsa_key.pem
rm public_ecdsa_key.pem

# Build and install library for apps
#meson setup -Dbuildtype=debug -Ddebugprints=false --prefix $GST_PLUGIN_PATH . build_lib_for_signing
#meson install -C build_lib_for_signing

#meson setup -Dbuildtype=debug -Ddebugprints=false --prefix $VALIDATOR_PATH . build_lib_for_validation
#meson install -C build_lib_for_validation

# Build and install apps
meson setup -Dsigner=true -Dbuildtype=debug --prefix $GST_PLUGIN_PATH . build_signer
meson install -C build_signer

meson setup -Dvalidator=true -Dbuildtype=debug --prefix $VALIDATOR_PATH . build_validator
meson install -C build_validator

# Copy file to current directory
cp examples/test-files/test_h264.mp4 .
$SIGNER test_h264.mp4
$VALIDATOR -c h264 signed_test_h264.mp4

cat validation_results.txt

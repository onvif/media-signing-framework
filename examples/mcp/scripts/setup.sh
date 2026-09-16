#!/bin/sh
set -eu

MCP_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
REPO_ROOT=$(CDPATH= cd -- "$MCP_DIR/../.." && pwd)
DEMO_DIR="$MCP_DIR/.demo"
FRAMEWORK_BUILD="$DEMO_DIR/framework-build"
FRAMEWORK_PREFIX="$DEMO_DIR/framework-prefix"

mkdir -p "$DEMO_DIR"
for tool in cc meson ninja pkg-config gst-inspect-1.0 node npm; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "Required tool '$tool' was not found. See docs/tutorial.md." >&2
    exit 1
  fi
done

if ! node -e 'const [major, minor] = process.versions.node.split(".").map(Number); process.exit(major > 22 || (major === 22 && minor >= 13) ? 0 : 1)'; then
  echo "Node.js 22.13 or later is required. See docs/tutorial.md." >&2
  exit 1
fi

for module in openssl gstreamer-1.0 gstreamer-app-1.0 gstreamer-pbutils-1.0 json-glib-1.0; do
  if ! pkg-config --exists "$module"; then
    echo "Required pkg-config module '$module' was not found. See docs/tutorial.md." >&2
    exit 1
  fi
done

for element in qtdemux h264parse h265parse appsink; do
  if ! gst-inspect-1.0 "$element" >/dev/null 2>&1; then
    echo "Required GStreamer element '$element' was not found. See docs/tutorial.md." >&2
    exit 1
  fi
done

if [ ! -f "$FRAMEWORK_BUILD/meson-private/coredata.dat" ]; then
  meson setup --prefix "$FRAMEWORK_PREFIX" -Dvalidator=true \
    "$REPO_ROOT" "$FRAMEWORK_BUILD"
else
  meson setup --reconfigure --prefix "$FRAMEWORK_PREFIX" -Dvalidator=true \
    "$REPO_ROOT" "$FRAMEWORK_BUILD"
fi
meson compile -C "$FRAMEWORK_BUILD"
meson install -C "$FRAMEWORK_BUILD"

if [ ! -d "$MCP_DIR/node_modules/@modelcontextprotocol/sdk" ]; then
  npm ci --prefix "$MCP_DIR" --cache "$DEMO_DIR/npm-cache"
fi

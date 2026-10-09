#!/bin/sh
set -eu

# A legacy volume must be exported by an authorized client, never loaded by Rusty.
# Choose a fresh mounted directory when /data contains old readable state.
exec mesh-lighthouse "${RUSTY_STATE_DIR:-/data}" "${RUSTY_HTTP_BIND:-0.0.0.0:8080}"

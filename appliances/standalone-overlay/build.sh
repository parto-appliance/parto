#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
export APPLIANCE_TYPE=standalone-overlay
export VERSION=${VERSION:-0.13.0}
export APPLIANCE_TITLE=Parto
export OVA_NOTES=${OVA_NOTES:-"Parto: local HTTPS management, browser peer-file exchange and live interface addresses."}
bash "$HERE/transport/build.sh"
exec bash "$HERE/../parto-vm/build.sh"

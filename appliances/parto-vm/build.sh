#!/usr/bin/env bash
# Construct a new guest disk in an isolated, privileged local Docker container.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
APPLIANCE_TYPE=${APPLIANCE_TYPE:-managed-overlay}
APPLIANCE_ARCH=${APPLIANCE_ARCH:-amd64}
case "$APPLIANCE_ARCH:$APPLIANCE_TYPE" in
  amd64:managed-overlay|amd64:standalone-overlay|arm64:standalone-overlay) ;;
  *) echo "Unsupported appliance architecture/family: $APPLIANCE_ARCH/$APPLIANCE_TYPE" >&2; exit 2 ;;
esac
case "$APPLIANCE_TYPE" in
  managed-overlay) STEM=parto-vm; DEFAULT_VOLUME=parto-vm-build-cache; DEFAULT_OUTPUT="$HERE/artifacts" ;;
  standalone-overlay) STEM=parto; DEFAULT_VOLUME=parto-standalone-build-cache; DEFAULT_OUTPUT="$REPO/appliances/standalone-overlay/artifacts" ;;
  *) echo "Unknown appliance type" >&2; exit 2 ;;
esac
[ "$APPLIANCE_ARCH" = amd64 ] || DEFAULT_VOLUME="$DEFAULT_VOLUME-$APPLIANCE_ARCH"
OUTPUT=${OUTPUT:-"$DEFAULT_OUTPUT"}
VERSION=${VERSION:-0.4.0}
BUILD_IMAGE=${BUILD_IMAGE:-parto-vm-builder:bookworm}
BUILD_VOLUME=${BUILD_VOLUME:-$DEFAULT_VOLUME}
CONSOLE_SOURCE_SHA=$(git -C "$REPO" rev-parse HEAD)
CONSOLE_SOURCE_DIRTY=false
[ -z "$(git -C "$REPO" status --porcelain)" ] || CONSOLE_SOURCE_DIRTY=true
mkdir -p "$OUTPUT"
if [ "${BUILD_MODE:-build}" != prepare ] && \
   { [ -e "$OUTPUT/$STEM-$VERSION-$APPLIANCE_ARCH.ova" ] || [ -e "$OUTPUT/$STEM-$VERSION-$APPLIANCE_ARCH-disk.vmdk" ]; }; then
  echo "Appliance $VERSION already exists; choose a fresh VERSION to preserve its artifact." >&2
  exit 2
fi
if [ "${BUILD_MODE:-build}" != prepare ] && [ "$APPLIANCE_TYPE" = managed-overlay ]; then
  python3 "$HERE/retain_artifacts.py" "$OUTPUT" --check-version "$VERSION"
fi
docker build -t "$BUILD_IMAGE" "$HERE"
docker volume create "$BUILD_VOLUME" >/dev/null
docker run --rm --privileged \
  --mount "type=bind,source=$REPO,target=/source,readonly" \
  --mount "type=bind,source=$OUTPUT,target=/output" \
  --mount "type=volume,source=$BUILD_VOLUME,target=/work" \
  -e "APPLIANCE_TITLE=${APPLIANCE_TITLE:-OVERLAY Virtual Appliance}" -e "APPLIANCE_TYPE=$APPLIANCE_TYPE" -e "APPLIANCE_ARCH=$APPLIANCE_ARCH" -e "APPLIANCE_VERSION=$VERSION" -e "BUILD_MODE=${BUILD_MODE:-build}" \
  -e "CONSOLE_SOURCE_SHA=$CONSOLE_SOURCE_SHA" -e "CONSOLE_SOURCE_DIRTY=$CONSOLE_SOURCE_DIRTY" \
  "$BUILD_IMAGE" -c 'cp /source/appliances/parto-vm/build-linux.sh /tmp/console-vm-build.sh; exec bash /tmp/console-vm-build.sh'

# Publish only a successful build. Host credentials never enter the guest.
echo 'Built locally; no upload or publication performed.'

# Prune only after a successful, validated build; prepare/failures keep history.
if [ "${BUILD_MODE:-build}" != prepare ] && [ "$APPLIANCE_TYPE" = managed-overlay ]; then
  python3 "$HERE/retain_artifacts.py" "$OUTPUT" --apply
fi

#!/usr/bin/env bash

set -Eeuo pipefail

PLATFORM_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
exec "${PLATFORM_DIRECTORY}/deploy/mineguard-linux.sh" "$@"

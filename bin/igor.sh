#!/bin/bash

set -e

BIN="$(cd "$(dirname "$0")" ; pwd)"
PROJECT="$(dirname "${BIN}")"
WORKSPACE="$(dirname "${PROJECT}")"
IGOR="${WORKSPACE}/igor"

source "${BIN}/lib-verbose.sh"
(
  cd "${PROJECT}"

  export RUST_LOG='info,igor=debug'

  "${IGOR}/target/debug/igor"
)
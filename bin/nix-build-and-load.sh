#!/bin/bash

set -e

BIN="$(cd "$(dirname "$0")" ; pwd)"

"${BIN}/nix-exec.sh" -c 'nix build .#dockerImage ; cat result' \
  | docker load

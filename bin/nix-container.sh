#!/bin/bash

set -e

BIN="$(cd "$(dirname "$0")" ; pwd)"
PROJECT="$(dirname "${BIN}")"

source "${BIN}/lib-verbose.sh"

if [[ ".$1" = '.--stop' ]]
then
  docker container rm -f nix-daemon
  exit 0
fi

if [[ ".$1" = '.--no-stop' ]]
then
  STATUS="$(docker inspect nix-daemon --format '{{.State.Status}}' 2>/dev/null)"
  if [[ ".${STATUS}" = '.running' ]]
  then
    exit 32
  fi
fi

MOUNT_STORE='true'
STORE_ROOT='/nix'
if [[ ".$1" = '.--no-store' ]]
then
  MOUNT_STORE='false'
  shift
elif [[ ".$1" = '.--store-root' ]]
then
  STORE_ROOT="$2"
  shift 2
fi

REBUILD='false'
DOCKER_BUILD_FLAGS=()
if [[ ".$1" = '.--rebuild' ]]
then
  REBUILD='true'
  DOCKER_BUILD_FLAGS+=('--no-cache')
fi

if "${REBUILD}" || [[ -z "$(docker image ls --format json 'rustigaan/nix:latest')" ]]
then
  docker build "${DOCKER_BUILD_FLAGS[@]}" -t 'rustigaan/nix:latest' -f "${PROJECT}/docker/nix/Dockerfile" "${PROJECT}/docker/nix"
fi

DOCKER_RUN_FLAGS=('--detach')
COMMAND=('/bin/bash' '-c' '/root/run-daemon.sh')
if [[ ".$1" = '.--no-daemon' ]]
then
  shift
  DOCKER_RUN_FLAGS=()
  COMMAND=()
fi

while [[ "$#" -gt 0 ]] && [[ ".$1" != '.--' ]]
do
    DOCKER_RUN_FLAGS+=("$1")
    shift
done

if [[ ".$1" = '.--' ]]
then
  shift
fi
log "Remaining arguments: [$*]"

if "${MOUNT_STORE}"
then
  docker volume create --driver local nix
  DOCKER_RUN_FLAGS+=(--mount "type=volume,source=nix,target=${STORE_ROOT}")
fi

SSH_DIR="${HOME}/.ssh"

## LOCAL="${PROJECT}/data/local"
LOCAL="${PROJECT}"

CONTAINER_WORK_DIR="${PWD}"
log "CONTAINER_WORK_DIR#LOCAL=[${CONTAINER_WORK_DIR#${LOCAL}}]"
log "LOCAL#CONTAINER_WORK_DIR=[${LOCAL#${CONTAINER_WORK_DIR}}]"
if [[ ".${CONTAINER_WORK_DIR#${LOCAL}}" = ".${CONTAINER_WORK_DIR}" ]] && [[ ".${LOCAL#${CONTAINER_WORK_DIR}}" = ".${LOCAL}" ]]
then
  CONTAINER_WORK_DIR="${LOCAL}"
fi
log "CONTAINER_WORK_DIR=[${CONTAINER_WORK_DIR}]"

docker container rm -f nix-daemon >/dev/null 2>&1 || true

if [[ -z "$(docker network inspect --format '{{.Name}}' nix-dev 2>/dev/null)" ]]
then
  docker network create nix-dev
fi

DOCKER_COMMAND=(docker run -ti --privileged \
    "${DOCKER_RUN_FLAGS[@]}" \
    --network nix-dev \
    --mount "type=bind,source=${SSH_DIR},target=/home/somebody/.ssh" \
    --mount "type=bind,source=${LOCAL},target=${LOCAL}" \
    -w "${CONTAINER_WORK_DIR}" \
    --name 'nix-daemon' --hostname 'nix-daemon' \
    'rustigaan/nix:latest' \
    "${COMMAND[@]}" "$@")
log "DOCKER_COMMAND=[${DOCKER_COMMAND[*]}]"
"${DOCKER_COMMAND[@]}"

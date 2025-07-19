#!/bin/bash

set -e

BIN="$(cd "$(dirname "$0")" ; pwd)"
PROJECT="$(dirname "${BIN}")"

source "${BIN}/lib-verbose.sh"

DOCKER_FLAGS=()
if [[ -t 0 ]] && [[ -t 1 ]]
then
  DOCKER_FLAGS+=('-t')
fi

USER_FLAGS=(-u somebody:somebody -e HOME=/home/somebody)
if [[ ".$1" = '.--root' ]]
then
  USER_FLAGS=(-e HOME=/root)
  shift
fi

COMMAND=('bash')
if [[ ".$1" = '.--no-bash' ]]
then
  COMMAND=()
  shift
fi

CONTAINER_WORK_DIR="${PWD}"
DOCKER_WORK_DIR=(-w "${CONTAINER_WORK_DIR}")
log "CONTAINER_WORK_DIR#LOCAL=[${CONTAINER_WORK_DIR#${PROJECT}}]"
log "LOCAL#CONTAINER_WORK_DIR=[${PROJECT#${CONTAINER_WORK_DIR}}]"
if [[ ".${CONTAINER_WORK_DIR#${PROJECT}}" = ".${CONTAINER_WORK_DIR}" ]] && [[ ".${PROJECT#${CONTAINER_WORK_DIR}}" = ".${PROJECT}" ]]
then
  DOCKER_WORK_DIR=()
fi
log "DOCKER_WORK_DIR=[${DOCKER_WORK_DIR[*]}]"

DOCKER_COMMAND=(docker exec "${USER_FLAGS[@]}" "${DOCKER_FLAGS[@]}" "${DOCKER_WORK_DIR[@]}" -i nix-daemon "${COMMAND[@]}" "$@")
log "DOCKER_COMMAND=${DOCKER_COMMAND[*]}"
"${DOCKER_COMMAND[@]}"

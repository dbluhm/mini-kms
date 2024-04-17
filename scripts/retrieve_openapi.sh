#!/bin/bash

cd "$(dirname "$0")/../" || exit
CONTAINER_RUNTIME=${CONTAINER_RUNTIME:-docker}
BUILD_CONTEXT="."
IMAGE_NAME=${IMAGE_NAME:-"mini-kms-openapi"}
PORT=${PORT:-8080}
URL=http://${DOCKER_CONTAINER_HOST:-localhost}:${PORT}/openapi.json
OUTPUT=${OUTPUT:-./openapi.json}


${CONTAINER_RUNTIME} build -t "${IMAGE_NAME}" ${BUILD_CONTEXT}
CONTAINER_ID=$(${CONTAINER_RUNTIME} run -d -p "${PORT}:80" "${IMAGE_NAME}")
# Make sure container gets terminated when we do
trap '$CONTAINER_RUNTIME kill ${CONTAINER_ID}' EXIT

WAIT_INTERVAL=${WAIT_INTERVAL:-3}
WAIT_ATTEMPTS=${WAIT_ATTEMPTS:-10}

for _ in $(seq 1 "$WAIT_ATTEMPTS"); do
    if ! curl -s -o /dev/null -w '%{http_code}' "${URL}" | grep "200" > /dev/null; then
        echo "Waiting for openapi.json..." 1>&2
        sleep "$WAIT_INTERVAL" &
        wait $!
    else
        break
    fi
done

curl --output "${OUTPUT}" "${URL}"

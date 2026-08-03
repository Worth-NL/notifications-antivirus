#!/bin/bash
DOCKER_IMAGE_NAME=notifications-antivirus

docker run -it --rm \
  --network notifynl-devcontainer_devcontainer_devcontainer \
  -e NOTIFY_ENVIRONMENT=development \
  -e FLASK_APP=application.py \
  -e FLASK_DEBUG=1 \
  -e AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID:-test} \
  -e AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY:-test} \
  -e AWS_ENDPOINT_URL=${AWS_ENDPOINT_URL:-http://ministack:4566} \
  -e NOTIFICATION_QUEUE_PREFIX=${NOTIFICATION_QUEUE_PREFIX} \
  -e SENTRY_ENABLED=${SENTRY_ENABLED:-0} \
  -e SENTRY_DSN=${SENTRY_DSN:-} \
  -e SENTRY_ERRORS_SAMPLE_RATE=${SENTRY_ERRORS_SAMPLE_RATE:-} \
  -e SENTRY_TRACES_SAMPLE_RATE=${SENTRY_TRACES_SAMPLE_RATE:-} \
  -v $(pwd):/home/vcap/app \
  ${DOCKER_ARGS} \
  ${DOCKER_IMAGE_NAME} \
  ${@}

#!/bin/bash

# Output command before executing
set -x

# Exit on error
set -e

# Source environment variables of the jenkins slave
# that might interest this worker.
function load_jenkins_vars() {
  if [ -e "jenkins-env" ]; then
    cat jenkins-env \
      | grep -E "(DEVSHIFT_TAG_LEN|DEVSHIFT_USERNAME|DEVSHIFT_PASSWORD|JENKINS_URL|GIT_BRANCH|GIT_COMMIT|BUILD_NUMBER|ghprbSourceBranch|ghprbActualCommit|BUILD_URL|ghprbPullId)=" \
      | sed 's/^/export /g' \
      > ~/.jenkins-env
    source ~/.jenkins-env
  fi
}

function install_deps() {
  # We need to disable selinux for now, XXX
  /usr/sbin/setenforce 0

  # Get all the deps in
  yum -y install \
    docker \
    make \
    git \
    curl

  service docker start

  echo 'CICO: Dependencies installed'
}

function cleanup_env {
  EXIT_CODE=$?
  echo "CICO: Cleanup environment: Tear down test environment"
  make integration-test-env-tear-down
  echo "CICO: Exiting with $EXIT_CODE"
}

function prepare() {
  # Let's test
  make docker-start
  make docker-check-go-format
  make docker-deps
  make docker-analyze-go-code
  make docker-generate
  make docker-build
  echo 'CICO: Preparation complete'
}

function run_tests_without_coverage() {
  make docker-test-unit
  make integration-test-env-prepare
  trap cleanup_env EXIT

  # Check that postgresql container is healthy
  check_postgres_healthiness

  make docker-test-migration
  make docker-test-integration
  make docker-test-remote
  echo "CICO: ran tests without coverage"
}

function check_postgres_healthiness(){
  echo "CICO: Waiting for postgresql container to be healthy...";
  while ! docker ps | grep postgres_integration_test | grep -q healthy; do
    printf .;
    sleep 1 ;
  done;
  echo "CICO: postgresql container is HEALTHY!";
}

function run_tests_with_coverage() {
  # Run the unit tests that generate coverage information
  make docker-test-unit-with-coverage
  make integration-test-env-prepare
  trap cleanup_env EXIT

  # Check that postgresql container is healthy
  check_postgres_healthiness

  # Run the integration tests that generate coverage information
  make docker-test-migration
  make docker-test-integration-with-coverage

  # Run the remote tests that generate coverage information
  make docker-test-remote-with-coverage

  # Output coverage
  make docker-coverage-all

  # Upload coverage to codecov.io
  cp tmp/coverage.mode* coverage.txt
  bash <(curl -s https://codecov.io/bash) -X search -f coverage.txt -t 8835a743-b3e5-4739-94df-84c145e61f14 #-X fix

  echo "CICO: ran tests and uploaded coverage"
}

function tag_push() {
  TARGET=$1
  docker tag fabric8-auth-deploy $TARGET
  docker push $TARGET
}

function deploy() {
  # Let's deploy
  make docker-image-deploy

  TAG=$(echo $GIT_COMMIT | cut -c1-${DEVSHIFT_TAG_LEN})
  REGISTRY="push.registry.devshift.net"

  if [ -n "${DEVSHIFT_USERNAME}" -a -n "${DEVSHIFT_PASSWORD}" ]; then
    docker login -u ${DEVSHIFT_USERNAME} -p ${DEVSHIFT_PASSWORD} ${REGISTRY}
  else
    echo "Could not login, missing credentials for the registry"
  fi

  tag_push ${REGISTRY}/fabric8-services/fabric8-auth:$TAG
  tag_push ${REGISTRY}/fabric8-services/fabric8-auth:latest
  echo 'CICO: Image pushed, ready to update deployed app'
}

function cico_setup() {
  load_jenkins_vars;
  install_deps;
  prepare;
}

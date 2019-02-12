#!/bin/bash

. cico_setup.sh

cico_setup;

make deps

TMP_PATH="$(readlink -f tmp)"
JOB_NAME="${JOB_NAME:-contract-testing-cico-job}"
BUILD_NUMBER="${BUILD_NUMBER:-0}"

ARTIFACTS_PATH="contracts/${JOB_NAME}/${BUILD_NUMBER}"

OUTPUT_DIR="$TMP_PATH/test"
mkdir -p "$OUTPUT_DIR/$ARTIFACTS_PATH"

F8_CLUSTER_DIR="$GOPATH/src/github.com/fabric8-services/fabric8-cluster"
go get github.com/fabric8-services/fabric8-cluster

# Add Pact CLI to PATH
export PATH="$TMP_PATH/pact/bin:$PATH"

# Ensure Pact CLI is installed
pact-mock-service version &> /dev/null
test_pact_exit=$?
if [ $test_pact_exit -ne 0 ]; then
    curl -L -s https://github.com/pact-foundation/pact-ruby-standalone/releases/download/v1.63.0/pact-1.63.0-linux-x86_64.tar.gz -o "$TMP_PATH/pact-cli.tar.gz"
    tar -xf "$TMP_PATH/pact-cli.tar.gz" --directory "$TMP_PATH"
fi

# Start Auth service
AUTH_CLUSTER_URL_SHORT="http://localhost:8087" make dev &> "$OUTPUT_DIR/$ARTIFACTS_PATH/test-auth.log" &
authpid=$!

## Wait for the Auth service to start up
mainpid=$$
(sleep 180; echo "Auth service startup failed."; kill $authpid; kill $mainpid) &
watchdogpid=$!
wait_period=5
echo "Starting local Auth service"
while [ $(curl -L --silent -XGET 'http://localhost:8089/api/status' > /dev/null; echo $?) -gt 0 ]; do
    echo "Waiting for Auth service for ${wait_period}s ...";
    sleep $wait_period;
done
echo "Auth service is up and running."
kill $watchdogpid

# Start Cluster service (Auth dependency)
CUR_DIR=$(pwd)
cd $F8_CLUSTER_DIR
F8_AUTH_URL="http://localhost:8089" make dev &> "$OUTPUT_DIR/$ARTIFACTS_PATH/test-cluster.log" &
clusterpid=$!

## Wait for the Cluster service to start up
(sleep 180; echo "Cluster service startup failed."; kill $clusterpid; kill $mainpid) &
watchdogpid=$!
wait_period=5
echo "Starting local Cluster service"
while [ $(curl -L --silent -XGET 'http://localhost:8087/api/status' > /dev/null; echo $?) -gt 0 ]; do
    echo "Waiting for Cluster service for ${wait_period}s ...";
    sleep $wait_period;
done
echo "Cluster service is up and running."
kill $watchdogpid

cd $CUR_DIR
# Run the contract tests
make test-contracts-provider-no-coverage |& tee "$OUTPUT_DIR/$ARTIFACTS_PATH/test.log"
testsexit=$?

# Delete sensitive files
rm -rvf $OUTPUT_DIR/contracts/pacts
rm -rvf test/contracts/provider/log

# Archive the test results
if [ "$ARCHIVE_ARTIFACTS" = "true" ]; then
    cd $OUTPUT_DIR
    LATEST_LINK_PATH="contracts/${JOB_NAME}/latest"
    ln -sfn "$BUILD_NUMBER" "$LATEST_LINK_PATH"

    key_path="$(readlink -f ../artifacts.key)"
    chmod 600 "$key_path"
    chown root:root "$key_path"
    rsync --password-file="$key_path" -qPHva --relative "./$ARTIFACTS_PATH" "$LATEST_LINK_PATH" devtools@artifacts.ci.centos.org::devtools/
    ARTIFACTS_UPLOAD_EXIT_CODE=$?

    echo
    echo

    if [ $ARTIFACTS_UPLOAD_EXIT_CODE -eq 0 ]; then
    echo "Artifacts were uploaded to http://artifacts.ci.centos.org/devtools/$ARTIFACTS_PATH"
    else
    echo "ERROR: Failed to upload artifacts to http://artifacts.ci.centos.org/devtools/$ARTIFACTS_PATH"
    fi

    echo
    echo
fi

kill $clusterpid
kill $authpid
exit $testsexit

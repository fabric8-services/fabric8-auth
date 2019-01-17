#!/bin/bash

. cico_setup.sh

cico_setup;

OUTPUT_DIR="${OUTPUT_DIR:-test/contracts/output}"
mkdir -p "$OUTPUT_DIR"

ARTIFACTS_DIR="contracts/${JOB_NAME}/${BUILD_NUMBER}"
mkdir -p "$OUTPUT_DIR/$ARTIFACTS_DIR"

make clean dev &> "$OUTPUT_DIR/$ARTIFACTS_DIR/test-auth.log" &
authpid=$!

# Wait for the Auth service to start up
mainpid=$$
(sleep 180; echo "Auth service startup timed out."; kill $authpid; kill $mainpid) &
wait_period=5
watchdogpid=$!
echo "Starting local Auth service"
while [ $(curl -L --silent -XGET 'http://localhost:8089/api/status' > /dev/null; echo $?) -gt 0 ]; do
    echo "Waiting for Auth service for ${wait_period}s ...";
    sleep $wait_period;
done
echo "Auth service is up and running."
kill $watchdogpid

# Run the contract tests
make test-contracts-provider-no-coverage |& tee "$OUTPUT_DIR/$ARTIFACTS_DIR/test.log"
testsexit=$?

# Delete sensitive files
rm -rvf test/contracts/pacts
rm -rvf test/contracts/provider/log

# Archive the test results
if [ "$ARCHIVE_ARTIFACTS" = "true" ]; then
    cd $OUTPUT_DIR
    LATEST_LINK_PATH="contracts/${JOB_NAME}/latest"
    ln -sfn "$BUILD_NUMBER" "$LATEST_LINK_PATH"

    key_path="$(readlink -f ../artifacts.key)"
    chmod 600 "$key_path"
    chown root:root "$key_path"
    rsync --password-file="$key_path" -qPHva --relative "./$ARTIFACTS_DIR" "$LATEST_LINK_PATH" devtools@artifacts.ci.centos.org::devtools/
    ARTIFACTS_UPLOAD_EXIT_CODE=$?

    echo
    echo

    if [ $ARTIFACTS_UPLOAD_EXIT_CODE -eq 0 ]; then
    echo "Artifacts were uploaded to http://artifacts.ci.centos.org/devtools/$ARTIFACTS_DIR"
    else
    echo "ERROR: Failed to upload artifacts to http://artifacts.ci.centos.org/devtools/$ARTIFACTS_DIR"
    fi

    echo
    echo
fi

kill $authpid
exit $testsexit

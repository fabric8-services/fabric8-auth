#!/bin/bash

. cico_setup.sh

CICO_RUN="${CICO_RUN:-true}"
if [ "$CICO_RUN" == "true" ]; then
    cico_setup;
    yum -y install epel-release;
    yum --enablerepo=centosplus --enablerepo=epel -y install  \
        chromium \
        chromium-headless \
        chromedriver \
        docker-compose \
        golang \
        make;
    export GOPATH="/tmp/go"
    F8_AUTH_DIR="$GOPATH/src/github.com/fabric8-services/fabric8-auth"
    mkdir -p $F8_AUTH_DIR
    mv * $F8_AUTH_DIR
    mv .[!.]* $F8_AUTH_DIR
    cd $F8_AUTH_DIR
fi

make build

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
wait_period=5
attempts=18

echo "Starting local Auth service"
for i in $(seq 1 $attempts); do
    echo "Attempt $i/$attempts..."
    response_head="$(curl -LI --silent -XGET 'http://localhost:8089/api/status' | head -n 1)"
    if [ -z "$response_head" ]; then
        echo "Service unreachable - waiting for Auth service for ${wait_period}s ...";
        sleep $wait_period;
    else
        response_code="$(echo $response_head | cut -d ' ' -f2)"
        if [ $response_code -eq 200 ]; then
            echo "The Auth service is up and running.";
            break;
        else 
            echo "Failed to start the Auth service";
            echo $response_head;
            kill $authpid;
            exit 1;
        fi
    fi
    if [ $i -eq $attempts ]; then
        echo "Auth service failed to start in $attempts attempts."
        kill $authpid;
        exit 1;
    fi
done

# Start Cluster service (Auth dependency)
CUR_DIR=$(pwd)
cd $F8_CLUSTER_DIR
F8_AUTH_URL="http://localhost:8089" make dev &> "$OUTPUT_DIR/$ARTIFACTS_PATH/test-cluster.log" &
clusterpid=$!

## Wait for the Cluster service to start up
echo "Starting local Cluster service"
for i in $(seq 1 $attempts); do
    echo "Attempt $i/$attempts..."
    response_head="$(curl -LI --silent -XGET 'http://localhost:8087/api/status' | head -n 1)"
    if [ -z "$response_head" ]; then
        echo "Service unreachable - waiting for Cluster service for ${wait_period}s ...";
        sleep $wait_period;
    else
        response_code="$(echo $response_head | cut -d ' ' -f2)"
        if [ $response_code -eq 200 ]; then
            echo "The Cluster service is up and running.";
            break;
        else 
            echo "Failed to start the Cluster service";
            echo $response_head;
            kill $clusterpid;
            kill $authpid;    
            exit 1;
        fi
    fi
    if [ $i -eq $attempts ]; then
        echo "Cluster service failed to start in $attempts attempts."
        kill $clusterpid;
        kill $authpid;
        exit 1;
    fi
done

cd $CUR_DIR
# Run the contract tests
make test-contracts-provider-no-coverage |& tee "$OUTPUT_DIR/$ARTIFACTS_PATH/test.log"
testsexit=${PIPESTATUS[0]} #capture exit status of the make command

# Delete sensitive files
if [ "$CICO_RUN" == "true" ]; then
    rm -rvf $OUTPUT_DIR/contracts/pacts
    rm -rvf test/contracts/provider/log
fi

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

exit $testsexit

#!/bin/bash

. cico_setup.sh

CICO_RUN="${CICO_RUN:-true}"
if [ "$CICO_RUN" == "true" ]; then
    artifacts_key="$(readlink -f ./artifacts.key)"
    artifacts_key_path="/tmp/artifacts.key"
    echo "Checking for $artifacts_key file..."
    if [ -f $artifacts_key ]; then
        echo "$artifacts_key found - preparing for archiving artifacts."
        chmod 600 "$artifacts_key"
        chown root:root "$artifacts_key"
        mv -vf "$artifacts_key" "$artifacts_key_path"
    else
        echo "$artifacts_key does not found!"
        exit 1
    fi
    load_jenkins_vars;
    if [ -e "jenkins-env.json" ]; then
        regex="PACT_*\
|ARCHIVE_ARTIFACTS\
|JOB_NAME\
|BUILD_NUMBER\
|OSIO_USERNAME\
|OSIO_PASSWORD\
|ONLINE_REGISTRATION_SERVICE_ACCOUNT_CLIENT_ID\
|ONLINE_REGISTRATION_SERVICE_ACCOUNT_CLIENT_SECRET"
        eval "$(./env-toolkit load -f jenkins-env.json --regex $regex)"
    fi
    install_deps;
    YUM_OPTS="-y -d1"
    yum $YUM_OPTS install epel-release;
    yum $YUM_OPTS --enablerepo=centosplus --enablerepo=epel install  \
        chromium \
        chromium-headless \
        chromedriver \
        docker-compose \
        golang \
        make;

    # Aviod "to many open files" error
    ulimit -Hn 999999
    ulimit -Sn 999999
    sysctl fs.inotify.max_user_watches=65536
    sysctl fs.inotify.max_user_instances=2048

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
LATEST_LINK_PATH="contracts/${JOB_NAME}/latest"

OUTPUT_DIR="$TMP_PATH/test"
mkdir -p "$OUTPUT_DIR/$ARTIFACTS_PATH"

F8_CLUSTER_DIR="$GOPATH/src/github.com/fabric8-services/fabric8-cluster"
if [ ! -d $F8_CLUSTER_DIR ]; then
    git clone https://github.com/fabric8-services/fabric8-cluster $F8_CLUSTER_DIR
fi

set +e

# Add Pact CLI to PATH
export PATH="$TMP_PATH/pact/bin:$PATH"

# Ensure Pact CLI is installed
pact-mock-service version &> /dev/null
test_pact_exit=$?
if [ $test_pact_exit -ne 0 ]; then
    curl -L -s https://github.com/pact-foundation/pact-ruby-standalone/releases/download/v1.64.0/pact-1.64.0-linux-x86_64.tar.gz -o "$TMP_PATH/pact-cli.tar.gz"
    tar -xf "$TMP_PATH/pact-cli.tar.gz" --directory "$TMP_PATH"
fi

# Start Auth service
AUTH_CLUSTER_URL_SHORT="http://localhost:8087" make dev &> "$OUTPUT_DIR/$ARTIFACTS_PATH/test-auth.log" &
authpid=$!

## Wait for the Auth service to start up
wait_period=10
attempts=18

final_exit=0

echo "Starting local Auth service"
sleep $wait_period
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
            final_exit=1;
        fi
    fi
    if [ $i -eq $attempts ]; then
        echo "Auth service failed to start in $attempts attempts."
        kill $authpid;
        final_exit=1;
    fi
done

# Start Cluster service (Auth dependency)

if [ $final_exit == 0 ]; then
    CUR_DIR=$(pwd)
    cd $F8_CLUSTER_DIR
    F8_AUTH_URL="http://localhost:8089" make dev &> "$OUTPUT_DIR/$ARTIFACTS_PATH/test-cluster.log" &
    clusterpid=$!

    ## Wait for the Cluster service to start up
    echo "Starting local Cluster service"
    sleep $wait_period
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
                final_exit=1;
            fi
        fi
        if [ $i -eq $attempts ]; then
            echo "Cluster service failed to start in $attempts attempts."
            kill $clusterpid;
            kill $authpid;
            final_exit=1;
        fi
    done

    cd $CUR_DIR
fi

if [ $final_exit == 0 ]; then
    # Run the contract tests
    make test-contracts-provider-no-coverage |& tee "$OUTPUT_DIR/$ARTIFACTS_PATH/test.log"
    tests_exit=${PIPESTATUS[0]} #capture exit status of the make command

    # Delete sensitive files
    if [ "$CICO_RUN" == "true" ]; then
        rm -rvf $OUTPUT_DIR/contracts/pacts
        rm -rvf test/contracts/provider/log
    fi
fi

set -x

# Archive the test results
if [ "$CICO_RUN" == "true" ] && [ "$ARCHIVE_ARTIFACTS" == "true" ]; then
    echo
    echo

    echo "Archiving artifacts to http://artifacts.ci.centos.org/devtools/$ARTIFACTS_PATH"
    cd $OUTPUT_DIR
    ln -sfn "$BUILD_NUMBER" "$LATEST_LINK_PATH"

    rsync --password-file="$artifacts_key_path" -qPHva --relative "./$ARTIFACTS_PATH" "$LATEST_LINK_PATH" devtools@artifacts.ci.centos.org::devtools/
    ARTIFACTS_UPLOAD_EXIT_CODE=$?

    if [ $ARTIFACTS_UPLOAD_EXIT_CODE -eq 0 ]; then
        echo "Artifacts were uploaded to http://artifacts.ci.centos.org/devtools/$ARTIFACTS_PATH"
    else
        echo "ERROR: Failed to upload artifacts to http://artifacts.ci.centos.org/devtools/$ARTIFACTS_PATH"
    fi

    echo
    echo
fi

RTN_CODE=$(($tests_exit + $final_exit))

exit $RTN_CODE

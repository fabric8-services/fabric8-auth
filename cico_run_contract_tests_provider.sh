#!/bin/bash

. cico_setup.sh

cico_setup;

make clean dev &> test/contracts/test-auth.log &
authpid=$!

# Wait for the Auth service to start up
mainpid=$$
(sleep 180; echo "Auth service startup timed out."; kill $authpid; kill $mainpid) &
wait_period=5
watchdogpid=$!
echo "Starting Auth service"
while [ $(curl -L --silent -XGET 'http://localhost:8089/api/status' > /dev/null; echo $?) -gt 0 ]; do
    echo "Waiting for Auth service for ${wait_period}s ...";
    sleep $wait_period;
done
echo "Auth service is up and running."
kill $watchdogpid

# Run the contract tests
make test-contracts-provider-no-coverage |& tee test/contracts/test.log
testsexit=$?

kill $authpid
exit $testsexit

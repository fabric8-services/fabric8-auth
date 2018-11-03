#!/bin/bash

. cico_setup.sh

load_jenkins_vars

if [ ! -f .cico-prepare ]; then
    install_deps
    prepare

    run_tests_without_coverage;

    generate_client_setup fabric8-auth auth tool fabric8-services fabric8-auth-client

    touch .cico-prepare
fi

deploy;

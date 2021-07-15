#!/bin/bash
set -ex

TRUFFLE="npx truffle"

function abigen() {
    srcs=(
        "IBCHost"
        "IBCHandler"
        "IBCIdentifier"
        "SimpleToken"
        "ICS20TransferBank"
        "ICS20Bank"
    )
    for src in "${srcs[@]}" ; do
        make abi SOURCE=${src}
    done
}

function deploy() {
    if [ -z "$network" ]; then
        echo "variable network must be set"
        exit 1
    fi
    if [ -z "$CONF_TPL" ]; then
        echo "variable CONF_TPL must be set"
        exit 1
    fi

    make docker-image
    make docker-run

    pushd ./contract
    ${TRUFFLE} migrate --reset --network=${network}
    ${TRUFFLE} exec ./confgen.js --network=${network}
    popd

    make docker-commit
    make docker-rm
}

function development {
    abigen

    network=development
    export CONF_TPL="$(pwd)/pkg/consts/contract.go:$(pwd)/scripts/template/contract.go.tpl"
    echo ${CONF_TPL}
    deploy
}

development

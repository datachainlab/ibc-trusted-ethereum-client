
include e2e/docker.mk

GO ?= go
LINTER ?= golangci-lint

.PHONY: lint test
lint:
	@${LINTER} run -v --tests

test:
	@${GO} test -v ./...

# for e2e
.PHONY: build-simd
build-simd:
	@${GO} build -o ./build/simd ./simapp/simd

.PHONY: build-tm-images
build-tm-images:
	${DOCKER_BUILD} \
		--build-arg CHAINID=ibc0 \
		--tag ${DOCKER_REPO}tendermint-chain0:${DOCKER_TAG} .
	${DOCKER_BUILD} \
    	--build-arg CHAINID=ibc1 \
    	--tag ${DOCKER_REPO}tendermint-chain1:${DOCKER_TAG} .

.PHONY: proto-gen
proto-gen:
	@echo "Generating Protobuf files"
	@{DOCKER} run -v ${CURDIR}:/workspace --workdir /workspace tendermintdev/sdk-proto-gen sh ./scripts/protocgen.sh

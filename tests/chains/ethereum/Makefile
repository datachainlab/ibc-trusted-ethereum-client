GETH_VERSION ?= v1.10.4
DOCKER_TAG   ?= latest

ABIGEN ?= docker run -it --rm -v $(CURDIR)/contract/build/abi:/contract/build/abi -v $(CURDIR)/pkg/contract:/pkg/contract ethereum/client-go:alltools-$(GETH_VERSION) abigen

.PHONY: setup
setup:
	./scripts/setup.sh

.PHONY: abi
abi:
ifdef SOURCE
	$(eval TARGET := $(shell echo ${SOURCE} | tr A-Z a-z))
	@mkdir -p ./contract/build/abi ./pkg/contract
	@mkdir -p ./pkg/contract/$(TARGET)
	@cat ./contract/build/contracts/${SOURCE}.json | jq ".abi" > ./contract/build/abi/${SOURCE}.abi
	$(ABIGEN) --abi ./contract/build/abi/${SOURCE}.abi --pkg $(TARGET) --out ./pkg/contract/$(TARGET)/$(TARGET).go
else
	@echo "'SOURCE={SOURCE}' is required"
endif

.PHONY: proto-gen
proto-gen:
	@echo "Generating Protobuf files"
	docker run --rm -v $(CURDIR):/workspace --workdir /workspace tendermintdev/sdk-proto-gen sh ./scripts/protocgen.sh

DOCKER_IMAGE_NAME=geth-ethclient
DOCKER_INTERMEDIATE_IMAGE_NAME=geth-ethclient-intermediate

.PHONY: docker-image
docker-image:
	docker build --rm --no-cache --pull \
	--build-arg GETH_VERSION=${GETH_VERSION} \
	-t $(DOCKER_INTERMEDIATE_IMAGE_NAME):$(DOCKER_TAG) ./Dockerfiles/geth

.PHONY: docker-run
docker-run:
	docker run -it -d --name $(DOCKER_INTERMEDIATE_IMAGE_NAME) \
	-p8545:8545 -p8546:8546 \
	$(DOCKER_INTERMEDIATE_IMAGE_NAME):$(DOCKER_TAG)

.PHONY: docker-commit
docker-commit:
	docker commit --pause=true $(DOCKER_INTERMEDIATE_IMAGE_NAME) $(DOCKER_IMAGE_NAME):$(DOCKER_TAG)

.PHONY: docker-rm
docker-rm:
	docker container rm -f $(DOCKER_INTERMEDIATE_IMAGE_NAME)
	docker rmi -f $(DOCKER_INTERMEDIATE_IMAGE_NAME)

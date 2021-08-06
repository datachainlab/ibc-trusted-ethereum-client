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

DOCKER_IMAGE_NAME=geth-ethclient
DOCKER_SCAFFOLD_IMAGE_NAME=geth-ethclient-scaffold

.PHONY: docker-image
docker-image:
	make docker-image-scaffold
	make docker-run-scaffold
	make deploy-contract
	make docker-commit
	make docker-rm-scaffold

.PHONY: docker-run
docker-run:
	docker run -it -d --name $(DOCKER_IMAGE_NAME) \
    	-p8545:8545 -p8546:8546 \
    	$(DOCKER_IMAGE_NAME):$(DOCKER_TAG)

.PHONY: docker-rm-container
docker-rm-container:
	docker container rm -f $(DOCKER_IMAGE_NAME)

.PHONY: docker-image-scaffold
docker-image-scaffold:
	docker build --rm --no-cache --pull \
	--build-arg GETH_VERSION=${GETH_VERSION} \
	-t $(DOCKER_SCAFFOLD_IMAGE_NAME):$(DOCKER_TAG) ./Dockerfiles/geth

.PHONY: docker-run-scaffold
docker-run-scaffold:
	docker run -it -d --name $(DOCKER_SCAFFOLD_IMAGE_NAME) \
	-p8545:8545 -p8546:8546 \
	$(DOCKER_SCAFFOLD_IMAGE_NAME):$(DOCKER_TAG)

.PHONY: deploy-contract
deploy-contract:
	cd contract && npm run migrate

.PHONY: docker-commit
docker-commit:
	docker commit --pause=true $(DOCKER_SCAFFOLD_IMAGE_NAME) $(DOCKER_IMAGE_NAME):$(DOCKER_TAG)

.PHONY: docker-rm-scaffold
docker-rm-scaffold:
	docker container rm -f $(DOCKER_SCAFFOLD_IMAGE_NAME)
	docker rmi -f $(DOCKER_SCAFFOLD_IMAGE_NAME)

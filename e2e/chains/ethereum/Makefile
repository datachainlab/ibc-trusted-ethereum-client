include ../../docker.mk

SCRIPT_DIR ?= $(CURDIR)/scripts
NETWORK_ID0 ?= 13370
NETWORK_ID1 ?= 13380

.PHONY: docker-images
docker-images:
	make up-scaffold
	make deploy-contract
	make save-contract-address
	make docker-commit
	make down-scaffold

.PHONY: deploy-contract
deploy-contract:
	make wait-for-launch ATTEMPT=30 CONTAINER=ethereum-geth0-scaffold
	cd contract && npm run migrate

.PHONY: up-scaffold
up-scaffold:
	NETWORK_ID0=${NETWORK_ID0} NETWORK_ID1=${NETWORK_ID1} \
	$(DOCKER_COMPOSE) up --build -d

.PHONY: down-scaffold
down-scaffold:
	$(DOCKER_COMPOSE) down --volumes --remove-orphans

.PHONY: save-contract-address
save-contract-address:
	$(SCRIPT_DIR)/docker/saveContractAddress.sh $(NETWORK_ID0)
	$(SCRIPT_DIR)/docker/saveContractAddress.sh $(NETWORK_ID1)

.PHONY: docker-commit
docker-commit:
	$(SCRIPT_DIR)/docker/commitImage.sh  $(DOCKER_REPO) $(DOCKER_TAG) ethereum-geth0 ethereum-geth0-scaffold $(NETWORK_ID0)
	$(SCRIPT_DIR)/docker/commitImage.sh  $(DOCKER_REPO) $(DOCKER_TAG) ethereum-geth1 ethereum-geth1-scaffold $(NETWORK_ID1)

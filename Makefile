REPO           ?= authexec/reactive-tools
TAG            ?= latest
VOLUME         ?= $(shell pwd)

run:
	docker run --rm -it --network=host -v $(VOLUME):/usr/src/app/ $(REPO):$(TAG) bash

pull:
	docker pull $(REPO):$(TAG)

build:
	docker build -t $(REPO):$(TAG) .

push: login
	docker push $(REPO):$(TAG)

login:
	docker login

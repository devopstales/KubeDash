codeSHELL=/bin/bash -o pipefail
export VERSION=0.1

.PHONY:	all
all:	 kubedash

.DEFAULT_GOAL := help

#help:	@ List available tasks on this project
help:
	@grep -E '[a-zA-Z\.\-]+:.*?@ .*$$' $(MAKEFILE_LIST)| tr -d '#'  | awk 'BEGIN {FS = ":.*?@ "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

#devel:	@ Build local kubedash devel image
devel:
	rm -rf docker/kubedash/kubedash
	cp -r src/kubedash docker/kubedash
	rm -rf docker/kubedash/kubedash/instance/
	rm -rf docker/kubedash/kubedash/tests/
	rm -rf docker/kubedash/kubedash/.pytest_cache/
	rm -rf docker/kubedash/kubedash/.vscode/
	rm -rf docker/kubedash/kubedash/__pycache__/
	rm -rf docker/kubedash/kubedash/functions/__pycache__/
	docker build -t devopstales/kubedash:$(VERSION)-devel docker/kubedash

devel-push:
	docker push devopstales/kubedash:$(VERSION)-devel
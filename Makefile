codeSHELL=/bin/bash -o pipefail
export VERSION=3.0.1

.ONESHELL: # Applies to every targets in the file!
.PHONY:	all
all:	 kubedash

.DEFAULT_GOAL := help

#help:	@ List available tasks on this project
help:
	@grep -E '[a-zA-Z\.\-]+:.*?@ .*$$' $(MAKEFILE_LIST)| tr -d '#'  | awk 'BEGIN {FS = ":.*?@ "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

#kubedash-build: @ Build local kubedash devel image
kubedash-build:
	rm -rf docker/kubedash/kubedash
	cp -r src/kubedash docker/kubedash/kubedash
	rm -rf docker/kubedash/kubedash/instance/
	rm -rf docker/kubedash/kubedash/database/*
	rm -rf docker/kubedash/kubedash/tests/
	rm -rf docker/kubedash/kubedash/.pytest_cache/
	rm -rf docker/kubedash/kubedash/.vscode/
	rm -rf docker/kubedash/kubedash/__pycache__/
	rm -rf docker/kubedash/kubedash/functions/__pycache__/
	docker build -t devopstales/kubedash:$(VERSION)-devel docker/kubedash

#kubedash-push: @ Push local kubedash devel image
kubedash-push:
	docker push devopstales/kubedash:$(VERSION)-devel

#kubedash-rm: @ Delete local kubedash devel image
kubedash-rm:
	docker image rm -f devopstales/kubedash:$(VERSION)-devel

#kdlogin-build: @ Build kdlogin binaris with go
kdlogin-build: |
	cd src/kdlogin
	go mod tidy
	sed -i "s|AppVersion = .*|AppVersion = \"${VERSION}\"|" main.go
	rm -rf dist/{windows,linux,osx,release}
	rm -f dist/choco/*.nupkg
	env CGO_ENABLED=0 go build -o dist/linux/kubectl-kdlogin main.go
	env CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o dist/osx/kubectl-kdlogin main.go
	env CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o dist/windows/kubectl-kdlogin.exe main.go

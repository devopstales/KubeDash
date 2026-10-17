BIN=kubedash
VERSION ?= 0.1.0

build:
	CGO_ENABLED=0 go build -ldflags "-X cmd.version=$(VERSION)" -o $(BIN) .

cross:
	for t in darwin_amd64 darwin_arm64 linux_amd64 linux_arm64 windows_amd64; do \
	  os=$${t%_*}; arch=$${t#*_}; ext=""; [ $$os = windows ] && ext=.exe; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -ldflags "-X cmd.version=$(VERSION)" -o dist/$(BIN)-$$os-$$arch$$ext .; \
	done

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
export CGO_ENABLED=0

.PHONY: tidy test build all clean
tidy:
	go mod tidy
test:
	go vet ./... && go test ./...
build: tidy
	go build -trimpath -ldflags "$(LDFLAGS)" -o dist/easm-agent .
all: tidy
	GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/easm-agent-linux-amd64 .
	GOOS=linux   GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/easm-agent-linux-arm64 .
	GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/easm-agent-windows-amd64.exe .
clean:
	rm -rf dist

.PHONY: build test test-race run run-simulator certs docker clean fmt vet

BINARY_DIR := bin

build:
	go build -o $(BINARY_DIR)/sentinel ./cmd/sentinel
	go build -o $(BINARY_DIR)/simulator ./cmd/simulator

test:
	go test ./...

test-race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

run: build
	./$(BINARY_DIR)/sentinel --config configs/sentinel.yaml

run-simulator: build
	./$(BINARY_DIR)/simulator --server https://localhost:8080 \
		--clients 50 --rps 20 --burst 10 --duration 30s --jitter 10ms

certs:
	bash scripts/gen_certs.sh

docker:
	docker build -t sentinel:latest .

clean:
	rm -rf $(BINARY_DIR)

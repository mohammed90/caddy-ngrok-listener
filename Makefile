.PHONY: lint
lint:
	golangci-lint run .

.PHONY: test
test:
	go test -coverprofile cover.out ./...

.PHONY: coverage
coverage: test
	go tool cover -html cover.out

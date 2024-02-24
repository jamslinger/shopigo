SRC := $(wildcard *.go)

clean:
	$(RM) -r $(BIN) cover.out cover.html

fmt:
	go mod tidy
	gofmt -w $(SRC)

lint:
	golangci-lint run -E gofmt,revive

test: cover.out

cover.out: $(SRC)
	go test -race -timeout 20s -coverprofile=$@ $(GOTESTFLAGS) $(PKGS)

cover.html: cover.out
	go tool cover -html=$< -o $@

coverage: cover.html

.PHONY: clean fmt lint test coverage

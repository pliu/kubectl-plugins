BINARY := kubectl-krb_keycloak
CMD := ./cmd/kubectl-krb_keycloak
DIST := dist

.PHONY: build test integration-test lint cross-build clean

build:
	go build -trimpath -o $(BINARY) $(CMD)

test:
	go test ./...

integration-test:
	./integration/run.sh

lint:
	go vet ./...

cross-build: clean
	mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o $(DIST)/$(BINARY)-linux-amd64 $(CMD)
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -o $(DIST)/$(BINARY)-darwin-arm64 $(CMD)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -o $(DIST)/$(BINARY)-windows-amd64.exe $(CMD)

clean:
	rm -rf $(DIST) $(BINARY)

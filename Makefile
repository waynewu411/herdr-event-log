.PHONY: fmt vet build test clean

BINARY := hook

# Checks formatting (like CI); does not rewrite files. Run `gofmt -w .`
# yourself to fix any files this reports.
fmt:
	@out="$$(gofmt -l .)"; \
	if [ -n "$$out" ]; then \
		echo "The following files are not gofmt'd:"; \
		echo "$$out"; \
		exit 1; \
	fi

vet:
	go vet ./...

build:
	go build -o $(BINARY) .

test:
	go test -race ./...

clean:
	rm -f $(BINARY)

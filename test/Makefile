lint:
	golangci-lint run --disable-all -E govet -E gofumpt -E megacheck ./...

test:
	go test -p 1 -v ./...

benchmark:
	go test -benchmem -run=^$ -bench .

all: build

run:
	go build -o cmd/example cmd/*.go
	./example
build: 
	go build -o cmd/example cmd/*.go
clean: 
	rm cmd/example
install: 
	go install
test: 
	go test
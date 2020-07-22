all: build

run:
	go build -o example cmd/*.go
	./example
build: 
	go build -o example cmd/*.go
clean: 
	rm example
install: 
	go install
test: 
	go test
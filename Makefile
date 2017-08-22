all: build

build: 
	go build -o example main/*.go
clean: 
	rm example
install: 
	go install
test: 
	go test
all: build

run:
	go build -o example main/*.go
	./example
build: 
	go build -o example main/*.go
clean: 
	rm example
install: 
	go install
test: 
	go test
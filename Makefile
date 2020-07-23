all: build

run:
	go build -o cmd/main cmd/*.go
	./cmd/main
build: 
	go build -o cmd/main cmd/*.go
clean: 
	rm cmd/main
install: 
	go install
test: 
	go test
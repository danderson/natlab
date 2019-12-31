.PHONY: all
all:
	go build .
	docker build -t natlab:testing .

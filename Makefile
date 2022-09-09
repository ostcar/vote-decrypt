build-dev:
	docker build . --target development --tag vote-decrypt-dev

proto:
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=require_unimplemented_servers=false:. --go-grpc_opt=paths=source_relative grpc/decrypt.proto

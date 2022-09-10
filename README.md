# Vote Decrypt

Vote Decrypt is a service to decrypt a list of encrypted votes and return then
in random order.

The service is only reachable via gPRC.


## Main Key File

The service needs a main key. This needs to be 32 byte of random. It is used to
sign the poll keys and to sign the voting result.

The main file can be created with

```
head /dev/urandom -c 32 > main_key
```

// TODO: Maybe support keys in PEM-Format.
// TODO: Give a way to calculate the public key from the private key


## Install and start

### From Source

To install the service from source, download the repository and call

```
go build
./vote-decrypt [MAIN_KEY]
```

### With Docker

The container needs a key file. As default, it lookt for it at
`/run/secrets/vote_main_key` inside the container. Another file (from inside the
container) can be choosen via the first argument. The file has to be mounted
inside the docker container.

```
docker run -v "$(pwd)"/main_key:/run/secrets/vote_main_key vote-decrypt
```

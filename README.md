# Vote Decrypt

Vote Decrypt is a service to decrypt a list of encrypted votes and return then
in random order.

The service is only reachable via gPRC.


## Install and run

### From Source

To install the service from source, download the repository and call

```
go build
./vote-decrypt
```

### With Docker

The container needs a key file. As default, it lookt for it at
`/run/secrets/vote_main_key` inside the container. Another file (from inside the
container) can be choosen via the first argument. The file has to be mounted
inside the docker container.

```
docker run -v "$(pwd)"/main_key:/run/secrets/vote_main_key vote-decrypt
```


## Main Key File

The service needs a main key. This has to be 32 random bytes. It is used to
sign the poll keys and to sign the voting result.

The main file can be created with

```
head /dev/urandom -c 32 > main.key
```

or with the vote-decrypt tool

```
vote-decrypt main-key KEYFILE
```


## Public Key

The users need the public key of the main key to make sure the data from the
vote-decrypt service was not altered with.

The public key can be created with:

```
vote-decrypt pub-key KEYFILE
```

The keys are in raw bytes. To decode it with base64 use

```
vote-decrypt pub-key KEYFILE --base64
```


## Help

To see the options for all commands of vote-decrypt, call:

```
vote-decrypt --help
```


## Storage

`vote-decrypt` saves some data for each started poll. Currently the only
supported storrage backend is the filesystem.

As default, the uses the folder `vote_data`. 

When a poll is started, a `.key`-file is created. It contains the private poll
key for the started key. KEEP THIS PRIVATE. This file is needed to decrypt the
poll after it is done. If this file gets lost, it is not possible to decrypt a
poll.

When a poll is stopped, a `.hash`-file is created. It contains the signature for
the poll result. The file makes sure, that stop can not be called with different data.


## Configuration

### Environment Variables

The service uses the following enironment variables:

* `VOTE_DECRYPT_PORT`: Port for the gRPC serice to listen to. Default is `9014`.
* `VOTE_DECRYPT_STORE`: Folder to store the poll keys. Default is `vote_data`.

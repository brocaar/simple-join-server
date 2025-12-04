# Simple Join Server

The Simple Join Server provides a LoRaWAN<sup>&reg;</sup> Join Server interface
implementing the `JoinReq` and `JoinAns` message-types as specified by the
LoRaWAN Backend Interface specification.

The Simple Join Server:

* provides a database (PostgreSQL) schema
* provides a server application handling requests
* does not provide a web-interface

## Database schema

The database schema provides tables for storing network-servers and their
auth. tokens and for storing devices and their root-keys, nonces etc. A
device can be associated with one or multiple network-servers.

## Server application

The server application (Simple Join Server) supports the `JoinReq` API request
and responds with a `JoinAns`.

## Web-interface

The Simple Join Server does not provide a web-interface for managing
network-servers and devices. The intention of this project is to provide
a skeleton that can be integrated with other interfaces.

## Building from source

### Requirements

Building ChirpStack MQTT Forwarder requires:

* [Nix](https://nixos.org/download.html) (recommended) and
* [Docker](https://www.docker.com/)

#### Nix

Nix is used for setting up the development environment which is used for local
development and for creating the binaries. Alternatively, you could install the
dependencies listed in `shell.nix` by hand.

#### Docker

Docker is used by [cross-rs](https://github.com/cross-rs/cross) for cross-compiling,
as well as some of the `make` commands.

### Starting the development shell

Run the following command to start the development shell:

```bash
nix-shell
```

#### Dependencies

Install the following command to install the development dependencies:

```bash
make dev-dependencies
```

#### Run tests

Execute the following command to run the tests:

```bash
make test
```

### Building binaries

Execute the following commands to build the binary:

```bash
# Only build binaries
make build
```

Compiled binaries are stored in the `./target` folder.

## Using the binary

See the output of `simple-join-server --help` for usage information.

## License

Simple Join Server is distributed under the MIT license. See also
[LICENSE](https://github.com/brocaar/simple-join-server/blob/master/LICENSE).

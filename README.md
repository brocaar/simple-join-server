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

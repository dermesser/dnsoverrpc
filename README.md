# dnsoverrpc

tunnels DNS queries via [`clusterrpc`](https://github.com/dermesser/clusterrpc).

Why? Because. In addition, it may provide you with some level of privacy as
`clusterrpc` can be made to operate over an encrypted connection very easily:
Just generate a keypair using the `crpc-keygen` binary from `clusterrpc`, and
supply the keys to server and client.

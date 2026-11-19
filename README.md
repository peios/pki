# Peios PKI

`pki` is the Peios certificate authority repository. It will contain the
`pkid` daemon, which owns CA keys and issues X.509 certificates, and the `pki`
command for administration.

The design and its decisions are recorded in Acta under PEI-1701.

`pki-core` is the portable certificate core: it builds certificates, CA
certificates and CRLs from approved profiles. `pki-policy` decides whether a
request is issued, from certificate templates and the name trees, and builds
its profile. Neither has Registry, token or operating-system dependencies;
pkid supplies configuration and access checks. The Registry configuration is
described in [pkid.regman](docs/pkid.regman).

## Build and test

```sh
pekit test -j 2 unit policy clippy doctests
```

The same checks run directly with Cargo:

```sh
cargo +1.98.1 test --workspace --locked
cargo +1.98.1 clippy --workspace --all-targets --locked -- -Dwarnings
```

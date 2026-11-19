# Peios PKI

`pki` is the Peios certificate authority repository. It will contain the
`pkid` daemon, which owns CA keys and issues X.509 certificates, and the `pki`
command for administration.

The design and its decisions are recorded in Acta under PEI-1701.

`pki-core` is the portable certificate core: it builds certificates, CA
certificates and CRLs from approved profiles. `pki-policy` decides whether a
request is issued, from certificate templates and the name trees, and builds
its profile. `pki-keys` stores CA keys through pluggable providers: key files
sealed under a passphrase, and online keys protected by access control. None
of them depends on the Registry, tokens or other Peios services; pkid
supplies configuration, access checks and the access-controlled key store. The
Registry configuration is described in [pkid.regman](docs/pkid.regman).

Keys, signing and randomness go through `peios-crypto`, from peios-rs.
Certificate request signatures are still checked by x509-parser until
PEI-1729 moves them to `peios-crypto` too.

## Build and test

```sh
pekit test -j 2 unit policy keys clippy doctests
```

The same checks run directly with Cargo:

```sh
cargo +1.98.1 test --workspace --locked
cargo +1.98.1 clippy --workspace --all-targets --locked -- -Dwarnings
```

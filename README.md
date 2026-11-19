# Peios PKI

`pki` is the Peios certificate authority repository. It will contain the
`pkid` daemon, which owns CA keys and issues X.509 certificates, and the `pki`
command for administration.

The design and its decisions are recorded in Acta under PEI-1701.

`pki-core` is the portable certificate core: it builds certificates, CA
certificates and CRLs from approved profiles. `pki-policy` decides whether a
request is issued, from certificate templates and the name trees, and builds
its profile. `pki-keys` stores CA keys through pluggable providers: key files
sealed under a passphrase, and online keys protected by access control.
`pki-store` is the CA database, in SQLite: requests, issued certificates and
revocations, with who decided each. `pki-pipeline` takes requests from
submission to issue, holding or refusal, and lets officers approve, deny and
revoke, whichever front end the request arrived through. None of them
depends on the Registry, tokens or other Peios services; pkid supplies
configuration, access checks and the access-controlled key store. The
Registry configuration is described in [pkid.regman](docs/pkid.regman).

All cryptography goes through `peios-crypto`, from peios-rs: keys, signing,
randomness and checking the signatures on certificate requests.

`pkid-core` is pkid's control wire, a PSPU §3.15 channel at
`/run/pkid/pki.sock`, and `pkid-client` is the client the `pki` command and
window use. They link libpeios.

## Build and test

```sh
pekit test -j 2 unit policy keys store pipeline wire client clippy doctests
```

`wire` and `client` test the crates that link libpeios, which pekit builds
from the SDK at the commit `pekit.lock` pins. Cargo builds only the portable
crates, the workspace's default members:

```sh
cargo +1.98.1 test --locked
cargo +1.98.1 clippy --all-targets --locked -- -Dwarnings
```

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

`pkid` is the service. It reads its configuration from the Registry, keeps
online CA keys in `/var/state/pki/keys`, readable by its service identity
alone, records everything in `/var/state/pki/pkid.db`, and serves requests on
its control socket, authorizing each against the caller's token. Its events
are described in [pkid.evman](docs/pkid.evman). An administrator provisions
its state directories and default configuration (`pkid::provision`).

CAs are created through pkid, which makes their keys and certificates and
records them under `Authorities`: roots, subordinates of a CA on the same
pkid, and subordinates signed elsewhere, which await their certificate until
it is installed. pkid can also sign a subordinate's request for a CA
elsewhere, import a CA from a sealed key file, and export a CA's key. A key
sealed under a passphrase is never kept open; each operation that signs with
one takes its passphrase.

`pkid-core` is pkid's control wire, a PSPU §3.15 channel at
`/run/pkid/pki.sock`, and `pkid-client` is the client the `pki` command and
window use. They link libpeios.

## Build and test

```sh
pekit test -j 2 unit policy keys store pipeline wire client daemon clippy doctests
pekit build -j 2 pkid
```

`wire`, `client` and `daemon` test the crates that link libpeios, which pekit
builds from the SDK at the commit `pekit.lock` pins. They run on any Linux
host; what needs a Peios kernel, the access checks, the socket's identity
and the key store's descriptors, is qualified in a Peios guest. Cargo builds only the portable
crates, the workspace's default members:

```sh
cargo +1.98.1 test --locked
cargo +1.98.1 clippy --all-targets --locked -- -Dwarnings
```

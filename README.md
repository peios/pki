# Peios PKI

`pki` is the Peios certificate authority repository. It contains the `pkid`
daemon, which owns CA keys and issues X.509 certificates, and the `pki`
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
its state directories and default configuration with `pki setup`.

CAs are created through pkid, which makes their keys and certificates and
records them under `Authorities`: roots, subordinates of a CA on the same
pkid, and subordinates signed elsewhere, which await their certificate until
it is installed. pkid can also sign a subordinate's request for a CA
elsewhere, import a CA from a sealed key file, and export a CA's key. A key
sealed under a passphrase is never kept open; each operation that signs with
one takes its passphrase.

`pkid-core` is pkid's control wire, a PSPU §3.15 channel at
`/run/pkid/pki.sock`, and `pkid-client` is the client the `pki` command and
window use. `pki-management` reads pki's Registry configuration, for pkid
and the pki tools, and provisions a machine. They link libpeios.

Each CA publishes CRLs: pkid signs them on a schedule, after revocations,
or at an officer's request, and writes them under `/var/state/pki/http`.
`pki-httpd` serves that folder, read-only, over HTTP at the CAs'
distribution points; it holds no keys and can't reach pkid.

`pki` is the command, described in [pki(8)](docs/man/pki.8). It manages CAs
through pkid, which authorizes each request by the caller's own token, and
asks for the passphrases of sealed keys on the terminal, or reads them from a
file for a script. Templates and names it writes to the Registry itself,
checked by pki-policy's rules first. `pki enroll` makes a key on the
requester's machine and writes it, with its certificates, as a PKCS #12
file: pkid sees only the request.

`pki --window` is the Certificate Authority window, for the GXWI desktop,
built with the `window` feature. It makes its changes by running `pki`'s own
commands, answering their prompts from what was typed into it, and asks pkid,
the Registry and peinit what the person may do before offering it.
`pki/dev.peios.pki.toml` is its launcher declaration (PGSS Applications)
and `pki/pki.svg` its icon, installed as `/usr/share/apps/dev.peios.pki.toml`
and `/usr/share/icons/base/dev.peios.pki.svg` by the package that installs
`pki`.

`registry.d` holds the Registry seeds that package installs: the pkid and
pki-httpd service definitions, which start neither, and the privileges of
their service identities. `pki setup` provisions the machine, then has both
services start at boot and starts them.

## Build and test

```sh
pekit test -j 2 unit policy keys store pipeline wire client daemon management cli httpd clippy doctests
pekit build -j 2 pkid pki pki_httpd
```

`wire`, `client`, `daemon`, `management`, `cli` and `httpd` test the crates that link libpeios, which pekit
builds from the SDK at the commit `pekit.lock` pins. They run on any Linux
host; what needs a Peios kernel, the access checks, the socket's identity
and the key store's descriptors, is qualified in a Peios guest. Cargo builds only the portable
crates, the workspace's default members:

```sh
cargo +1.98.1 test --locked
cargo +1.98.1 clippy --all-targets --locked -- -Dwarnings
```

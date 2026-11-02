# WSS test certificates — never use outside tests

These self-signed CA and server certificates, and the server private key, are
public test fixtures generated solely for local TLS tests. The server cert is
signed by the fixture CA and has the single SAN `DNS:localhost`; it deliberately
has no IP SAN so hostname mismatch can be tested. The CA signing key is not
included. These credentials are public, provide no security, and must never be
installed as trusted roots or used for production services. Certificate expiry
is finite; regenerate the complete fixture set when necessary. The tests are
written but have not been executed.

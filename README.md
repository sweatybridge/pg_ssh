# pg_ssh

Run remote commands over SSH **from inside PostgreSQL**.

```sql
SELECT stdout, exit_code
  FROM ssh.ssh_exec('web-1', 'uname -a; uptime');
```

`pg_ssh` exposes a single function, `ssh.ssh_exec(host_name text, command text)`,
that returns `TABLE(stdout text, stderr text, exit_code int)`. It connects with
[libssh2] (via the Rust [`ssh2`] crate) and authenticates with
[`Session::userauth_pubkey_memory`][mem], so the PEM private key is handed to
libssh2 **directly from process memory and is never written to the filesystem**.

[libssh2]: https://libssh2.org/
[`ssh2`]: https://crates.io/crates/ssh2
[mem]: https://docs.rs/ssh2/0.9/ssh2/struct.Session.html#method.userauth_pubkey_memory

## Security model

| concern | how it's handled |
|---|---|
| **Private keys** | Stored only in the `ssh.hosts` catalog (in the data directory). During auth they are passed to libssh2 from memory — **never** materialized as a temp file on disk. |
| **Catalog access** | `ssh.hosts` is locked to its owner: `REVOKE ALL … FROM PUBLIC`. Only the superuser who ran `CREATE EXTENSION` can read or write it. |
| **Caller privileges** | `ssh.ssh_exec` is `SECURITY DEFINER` owned by that superuser, with a pinned `search_path = pg_catalog, ssh`. Unprivileged roles can be granted `EXECUTE` and run *approved* commands on *pre-registered* hosts — they see the result, never the keys. |
| **Host identity** | Each profile may pin a `host_key_fingerprint` (lowercase hex SHA-256 of the server host key). If set, `ssh_exec` refuses to connect on mismatch. |

> The default bootstrap grants `EXECUTE` to `PUBLIC` so the extension is usable
> out of the box. If you'd rather restrict who can run remote commands, run
> `REVOKE EXECUTE ON FUNCTION ssh.ssh_exec(text,text) FROM PUBLIC;` then
> `GRANT EXECUTE … TO <role>;`.

The catalog itself is **not** encrypted at rest — it is protected by
superuser-only table privileges, exactly like `postgres_fdw` user-mapping
passwords. If you need encryption at rest, store the PEM column
`pgp_sym_encrypt(...)`-ed and decrypt it inside `load_host_config` (requires
`pgcrypto`).

## The catalog

```sql
\d ssh.hosts
                       Table "ssh.hosts"
        Column        |  Type   | Notes
----------------------+---------+----------------------------------------------
 host_name            | text    | primary key — the name you pass to ssh_exec
 host                 | text    | hostname or IP
 port                 | integer | default 22
 username             | text    | remote login user
 public_key           | text    | optional; derived from private_key if NULL
 private_key          | text    | PEM private key (in-memory only)
 passphrase           | text    | optional, for encrypted keys
 host_key_fingerprint | text    | optional hex SHA-256 of the server host key
```

## Requirements

* PostgreSQL **18** (13–17 also build via the `pgXX` features)
* Rust toolchain (stable)
* [`cargo-pgrx`][cpgrx] **0.19.1** — must match the `pgrx` crate version exactly
* System packages (Debian/Ubuntu):

  ```bash
  sudo apt-get install -y build-essential pkg-config libclang-dev \
    libssl-dev libssh2-1-dev zlib1g-dev libreadline-dev
  ```

[cpgrx]: https://crates.io/crates/cargo-pgrx

## Build & install

```bash
# 1. One time: build a PostgreSQL 18 from source for pgrx to test against.
cargo pgrx init --pg18 download

# 2. Compile and install the extension into that PG18.
cargo pgrx install --pg18

# 3. In a database:
CREATE EXTENSION pg_ssh;
```

For a system-installed PostgreSQL, point pgrx at its `pg_config` instead:

```bash
cargo pgrx init --pg18 $(pg_config --bindir)/..
cargo pgrx install --pg-config $(which pg_config)
```

## Usage

Register a host (the PEM key can span multiple lines — use dollar-quoting):

```sql
INSERT INTO ssh.hosts
  (host_name, host, port, username, private_key, host_key_fingerprint)
VALUES
  ('web-1', '10.0.0.5', 22, 'deploy',
   $$-----BEGIN OPENSSH PRIVATE KEY-----
   ...
   -----END OPENSSH PRIVATE KEY-----$$,
   'b3f7...e2a0');  -- hex sha256 of the server host key (optional)
ON CONFLICT (host_name) DO UPDATE SET
  host = EXCLUDED.host,
  username = EXCLUDED.username,
  private_key = EXCLUDED.private_key;
```

Run a command:

```sql
SELECT * FROM ssh.ssh_exec('web-1', 'systemctl is-active nginx');
--  stdout | stderr | exit_code
-- --------+--------+-----------
--  active |        |         0
```

### Getting the host key fingerprint

`host_key_fingerprint` is the lowercase hex SHA-256 of the server's host key.
From any machine that trusts the host:

```bash
ssh-keyscan -t ed25519,rsa,ecdsa HOST 2>/dev/null \
  | ssh-keygen -E sha256 -lf -
# strip the leading "SHA256:" and base64, or compute the raw-digest hex:
ssh-keyscan -t ed25519 HOST 2>/dev/null \
  | awk '{print $3}' | base64 -d | sha256sum
# -> the hex string to store in host_key_fingerprint
```

> The fingerprint is of the **raw host key**, matching what libssh2's
> `host_key_hash(SHA256)` returns. The `base64 -d | sha256sum` recipe above
> produces exactly that.

## OpenSSL / libssh2 linkage (important)

PostgreSQL itself is usually built against OpenSSL. `libssh2` also needs a
crypto backend. To avoid two copies of OpenSSL colliding inside one backend
process, this extension links the **system, dynamically-linked `libssh2`**,
which in turn links the **same** system `libssl.so` that PostgreSQL uses. Do
**not** enable `vendored-openssl` or statically link a separate OpenSSL into the
extension. If you build PostgreSQL with a non-default OpenSSL, build libssh2
against that same one.

## Limitations

* `ssh_exec` performs **blocking** I/O in the backend. A slow/dead remote will
  hold the backend for up to `SSH_TIMEOUT_MS` (60 s) before erroring. Don't call
  it from performance-sensitive paths.
* Postgres query cancellation (`Ctrl-C`) is best-effort: a blocked libssh2 call
  may not return until its socket times out.
* Output is decoded with `String::from_utf8_lossy`; binary stdout is preserved
  lossily.
* stdout and stderr are drained concurrently so a process cannot deadlock the
  channel by filling one stream.

## Project layout

```
src/lib.rs        ssh_exec, SPI catalog lookup, libssh2 exec, bootstrap SQL
pg_ssh.control    extension control file
Cargo.toml        pgrx 0.19.1 + ssh2 0.9.5
live_test.sql     manual end-to-end smoke test (needs a reachable sshd)
```

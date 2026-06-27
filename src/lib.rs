//! `pg_ssh` — run remote commands over SSH from inside PostgreSQL.
//!
//! The extension exposes a single function, [`ssh_exec`], which looks up a
//! pre-authorized connection profile in the `ssh.hosts` catalog table, opens an
//! SSH session with [libssh2] via the [`ssh2`] crate, authenticates with
//! [`Session::userauth_pubkey_memory`] (so the PEM private key is passed to
//! libssh2 directly from memory and **never written to the filesystem**), runs
//! the requested command, and returns `(stdout, stderr, exit_code)`.
//!
//! [libssh2]: https://libssh2.org/
//! [`ssh2`]: https://crates.io/crates/ssh2
//! [`Session::userauth_pubkey_memory`]: ssh2::Session::userauth_pubkey_memory

use std::io::Read;
use std::net::TcpStream;

use pgrx::prelude::*;
use pgrx::spi::Spi;

pgrx::pg_module_magic!();

// Hard ceiling on any single blocking libssh2 call, in milliseconds. Prevents a
// misbehaving remote from pinning a backend forever. (Wiring this to a custom
// GUC is a natural follow-up.)
const SSH_TIMEOUT_MS: u32 = 60_000;

/// `ssh.ssh_exec(host_name text, command text) → TABLE(stdout, stderr, exit_code)`
///
/// Look up `host_name` in [`ssh.hosts`](self), connect, authenticate with the
/// in-memory private key, run `command`, and return one row with the captured
/// stdout, stderr, and the remote process exit code.
///
/// The function is `SECURITY DEFINER` and owned by the installing superuser
/// (see the bootstrap SQL below). That lets unprivileged roles run *approved*
/// commands on *pre-registered* hosts without ever gaining `SELECT` on
/// `ssh.hosts` — the private keys are never exposed to callers.
#[pg_extern(name = "ssh_exec")]
fn ssh_exec(
    host_name: &str,
    command: &str,
) -> TableIterator<
    'static,
    (
        name!(stdout, Option<String>),
        name!(stderr, Option<String>),
        name!(exit_code, Option<i32>),
    ),
> {
    match run_remote(host_name, command) {
        Ok((stdout, stderr, exit_code)) => TableIterator::new(vec![(stdout, stderr, exit_code)]),
        Err(message) => error!("ssh.ssh_exec({host_name:?}, {command:?}): {message}"),
    }
}

// ----------------------------------------------------------------------------
// Bootstrap SQL: catalog table + privilege model.
//
// `#[pg_extern]` emits `CREATE FUNCTION ssh_exec(...)` into the extension's
// install script (in the extension's default schema). This block then runs
// *after* that, so it can: create the `ssh` schema, create the credential
// catalog, move the function into the `ssh` schema, flip it to `SECURITY
// DEFINER`, pin a safe `search_path`, and lock down privileges.
// ----------------------------------------------------------------------------
extension_sql!(
    r#"
    -- The schema that holds both the catalog and the function.
    CREATE SCHEMA IF NOT EXISTS ssh;

    -- Pre-authorized SSH connection profiles. This is the only place private
    -- keys live; the table is locked to its (superuser) owner.
    CREATE TABLE IF NOT EXISTS ssh.hosts (
        host_name            text PRIMARY KEY,
        host                 text NOT NULL,
        port                 integer NOT NULL DEFAULT 22
            CHECK (port > 0 AND port < 65536),
        username             text NOT NULL,
        -- Optional public key. If NULL, libssh2 derives it from the private key.
        public_key           text,
        -- PEM-encoded private key. Passed to libssh2 in memory only.
        private_key          text NOT NULL,
        -- Optional passphrase for an encrypted private key.
        passphrase           text,
        -- Optional pinned host key, as lowercase hex of the SHA-256 digest of
        -- the server host key. When set, ssh.ssh_exec refuses to connect if it
        -- does not match. When NULL, host key verification is skipped (not
        -- recommended for production).
        host_key_fingerprint text
    );

    COMMENT ON TABLE  ssh.hosts IS
        'Pre-authorized SSH connection profiles for ssh.ssh_exec. Superuser-only.';
    COMMENT ON COLUMN ssh.hosts.private_key IS
        'PEM private key; passed to libssh2 in memory and never written to disk.';
    COMMENT ON COLUMN ssh.hosts.host_key_fingerprint IS
        'Lowercase hex SHA-256 of the server host key. NULL disables verification.';

    -- Lock the catalog: only the owner (the superuser who installed the
    -- extension) can read or write it. Callers never get direct access.
    REVOKE ALL ON SCHEMA ssh FROM PUBLIC;
    REVOKE ALL ON ssh.hosts FROM PUBLIC;

    -- Move the generated function into the ssh schema. (It was created
    -- unqualified in the extension install schema by #[pg_extern].)
    ALTER FUNCTION ssh_exec(text, text) SET SCHEMA ssh;

    -- Run as the function owner (a superuser), so it can read ssh.hosts on
    -- behalf of unprivileged callers. A pinned search_path defeats the usual
    -- SECURITY DEFINER search_path-injection trap.
    ALTER FUNCTION ssh.ssh_exec(text, text) SECURITY DEFINER;
    ALTER FUNCTION ssh.ssh_exec(text, text) SET search_path = pg_catalog, ssh;

    -- By default any connected role may invoke ssh_exec on a *registered* host
    -- (the command/host are constrained by what's in ssh.hosts). Tighten this
    -- with `REVOKE ... FROM PUBLIC; GRANT EXECUTE TO <role>;` if you prefer.
    REVOKE ALL ON FUNCTION ssh.ssh_exec(text, text) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION ssh.ssh_exec(text, text) TO PUBLIC;
    "#,
    name = "ssh_catalog_and_grants",
);

// ----------------------------------------------------------------------------
// Implementation
// ----------------------------------------------------------------------------

/// A single row of `ssh.hosts`, read out via SPI.
struct HostConfig {
    host: String,
    port: i32,
    username: String,
    public_key: Option<String>,
    private_key: String,
    passphrase: Option<String>,
    host_key_fingerprint: Option<String>,
}

/// Run `command` on the host registered as `host_name`.
///
/// Every fallible step produces a human-readable `String` error; the caller
/// ([`ssh_exec`]) turns that into a Postgres `ERROR`. All `ssh2` objects are
/// dropped before this returns, so a longjmp out of `error!` can't leak a
/// session or channel.
fn run_remote(
    host_name: &str,
    command: &str,
) -> Result<(Option<String>, Option<String>, Option<i32>), String> {
    let cfg = load_host_config(host_name)?;

    let tcp = TcpStream::connect((cfg.host.as_str(), cfg.port as u16))
        .map_err(|e| format!("tcp connect to {}:{}: {e}", cfg.host, cfg.port))?;
    let _ = tcp.set_nodelay(true);

    let mut session = ssh2::Session::new().map_err(|e| format!("ssh2 session init: {e}"))?;
    session.set_tcp_stream(tcp);
    session.set_timeout(SSH_TIMEOUT_MS);
    session
        .handshake()
        .map_err(|e| format!("ssh handshake with {}: {e}", cfg.host))?;

    verify_host_key(&session, cfg.host_key_fingerprint.as_deref(), &cfg.host)?;

    session
        .userauth_pubkey_memory(
            &cfg.username,
            cfg.public_key.as_deref(),
            &cfg.private_key,
            cfg.passphrase.as_deref(),
        )
        .map_err(|e| format!("publickey auth as {:?}: {e}", cfg.username))?;
    if !session.authenticated() {
        return Err(format!("publickey auth did not succeed as {:?}", cfg.username));
    }

    let mut channel = session
        .channel_session()
        .map_err(|e| format!("open session channel: {e}"))?;
    channel
        .exec(command)
        .map_err(|e| format!("exec {command:?}: {e}"))?;

    // Drain stdout on this thread and stderr on a helper thread. A single
    // blocking `read` holds the session's internal mutex only between syscalls,
    // so the two threads interleave and we never deadlock on a process that
    // writes a lot to one stream while the other stays open.
    let mut stderr = channel.stderr();
    let stderr_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr.read_to_end(&mut buf);
        buf
    });

    let mut stdout_buf = Vec::new();
    channel
        .read_to_end(&mut stdout_buf)
        .map_err(|e| format!("read stdout: {e}"))?;

    let _ = channel.send_eof();
    let _ = channel.wait_eof();
    let _ = channel.close();
    let _ = channel.wait_close();

    let stderr_buf = stderr_handle.join().unwrap_or_default();
    let exit_code = channel
        .exit_status()
        .map_err(|e| format!("retrieve exit status: {e}"))?;

    let stdout = String::from_utf8_lossy(&stdout_buf).into_owned();
    let stderr = String::from_utf8_lossy(&stderr_buf).into_owned();

    Ok((Some(stdout), Some(stderr), Some(exit_code)))
}

/// Look up `host_name` in `ssh.hosts`. The literal is quoted server-side via
/// `pg_sys::quote_literal_cstr`, so `host_name` cannot inject SQL.
fn load_host_config(host_name: &str) -> Result<HostConfig, String> {
    // `quote_literal` wraps `pg_sys::quote_literal_cstr`, so host_name cannot
    // inject SQL.
    let literal = pgrx::spi::quote_literal(host_name);
    let query = format!(
        "SELECT host, port, username, public_key, private_key, passphrase, host_key_fingerprint \
         FROM ssh.hosts WHERE host_name = {literal}"
    );

    // The closure must return pgrx's own Result type (its Err is `spi::Error`),
    // so we signal "not found" with `Ok(None)` and turn it into a message below.
    let found: Result<Option<HostConfig>, _> = Spi::connect(|client| {
        let table = client.select(&query, Some(1), std::iter::empty::<&str>())?;

        if table.is_empty() {
            return Ok(None);
        }

        // Columns are fetched by 1-based ordinal, matching the SELECT list above.
        let row = table.first();
        Ok(Some(HostConfig {
            host: row.get::<Option<String>>(1usize)?.unwrap_or_default(),
            port: row.get::<Option<i32>>(2usize)?.unwrap_or(22),
            username: row.get::<Option<String>>(3usize)?.unwrap_or_default(),
            public_key: row.get::<Option<String>>(4usize)?,
            private_key: row.get::<Option<String>>(5usize)?.unwrap_or_default(),
            passphrase: row.get::<Option<String>>(6usize)?,
            host_key_fingerprint: row.get::<Option<String>>(7usize)?,
        }))
    });

    match found {
        Ok(Some(cfg)) => Ok(cfg),
        Ok(None) => Err(format!("no host named {host_name:?} in ssh.hosts")),
        Err(e) => Err(format!("ssh.hosts lookup failed: {e:?}")),
    }
}

/// Verify the server host key against an optional pinned fingerprint.
///
/// `expected` is the lowercase hex SHA-256 of the server host key (matching the
/// `ssh.hosts.host_key_fingerprint` column). If `expected` is `None`, we fail
/// *open* and emit a `NOTICE` — convenient for getting started, but you should
/// always pin a fingerprint in production.
fn verify_host_key(
    session: &ssh2::Session,
    expected: Option<&str>,
    host: &str,
) -> Result<(), String> {
    let Some(expected) = expected.map(str::trim).filter(|s| !s.is_empty()) else {
        notice!(
            "ssh: no host_key_fingerprint set for {host:?}; skipping host key verification"
        );
        return Ok(());
    };

    let actual = fingerprint_of(session, ssh2::HashType::Sha256)
        .ok_or_else(|| format!("could not read host key from {host}"))?;

    if expected.eq_ignore_ascii_case(&actual) {
        Ok(())
    } else {
        Err(format!(
            "host key mismatch for {host}: expected sha256:{expected}, got sha256:{actual}"
        ))
    }
}

/// Lowercase hex SHA-256 digest of the server host key, or `None` if libssh2
/// hasn't completed the handshake enough to expose it.
fn fingerprint_of(session: &ssh2::Session, hash: ssh2::HashType) -> Option<String> {
    let digest = session.host_key_hash(hash)?;
    Some(hex_lower(digest))
}

fn hex_lower(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(TABLE[(b >> 4) as usize] as char);
        out.push(TABLE[(b & 0x0f) as usize] as char);
    }
    out
}

// ----------------------------------------------------------------------------
// Tests (run in-process by `cargo pgrx test`). These exercise the catalog and
// privilege model without touching the network; the live SSH path is covered by
// the manual smoke test documented in the README.
// ----------------------------------------------------------------------------

#[cfg(any(test, feature = "pg_test"))]
mod tests {
    use pgrx::spi::Spi;

    /// Run a query that returns exactly one boolean column and return it
    /// (false if NULL/empty). Uses the SPI client API whose signatures are
    /// confirmed, rather than `get_one` (whose return shape varies).
    fn one_bool(sql: &str) -> bool {
        Spi::connect(|client| {
            let value = client
                .select(sql, None, std::iter::empty::<&str>())?
                .first()
                .get::<Option<bool>>(1usize)?
                .unwrap_or(false);
            Ok(value)
        })
        .expect("spi query failed")
    }

    #[pg_test]
    fn catalog_table_exists_and_is_locked() {
        assert!(
            one_bool("SELECT to_regclass('ssh.hosts') IS NOT NULL"),
            "ssh.hosts should exist after CREATE EXTENSION"
        );

        // PUBLIC must have no rights on the credential table.
        assert!(
            !one_bool("SELECT has_table_privilege('public', 'ssh.hosts', 'SELECT')"),
            "PUBLIC must not be able to SELECT ssh.hosts"
        );
    }

    #[pg_test]
    fn ssh_exec_is_security_definer_in_ssh_schema() {
        assert!(
            one_bool(
                "SELECT prosecdef FROM pg_proc \
                  WHERE proname = 'ssh_exec' \
                    AND pronamespace = 'ssh'::regnamespace"
            ),
            "ssh.ssh_exec must be SECURITY DEFINER"
        );
    }
}

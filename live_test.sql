-- Manual end-to-end smoke test for pg_ssh.
--
-- This is NOT part of the automated `cargo pgrx test` suite (it needs a real,
-- reachable sshd). Run it by hand against a cluster that has the extension
-- installed, after standing up a test sshd and a keypair, e.g.:
--
--   # one-time setup
--   ssh-keygen -t ed25519 -N '' -f /tmp/pgssh_id
--   # start a local sshd that trusts /tmp/pgssh_id.pub for $USER
--
-- Then connect with psql and \i live_test.sql, having set :FP to the
-- hex sha256 of the sshd host key and :PORT / :USER / :KEY to taste.

-- 1. Register the host (replace the placeholders / paste the real key).
INSERT INTO ssh.hosts (host_name, host, port, username, private_key, host_key_fingerprint)
VALUES (
  'local',
  '127.0.0.1',
  :'PORT',
  :'USER',
  :'KEY',
  :'FP'
)
ON CONFLICT (host_name) DO UPDATE SET
  port = EXCLUDED.port,
  private_key = EXCLUDED.private_key,
  host_key_fingerprint = EXCLUDED.host_key_fingerprint;

-- 2. A clean command: exit 0, captured stdout, empty stderr.
SELECT stdout, stderr, exit_code
  FROM ssh.ssh_exec('local', 'echo hello-pg-ssh');

-- 3. A failing command: non-zero exit code + stderr captured.
SELECT stdout, stderr, exit_code
  FROM ssh.ssh_exec('local', 'ls /no/such/path');

-- 4. The remote shell sees a normal environment.
SELECT exit_code, stdout
  FROM ssh.ssh_exec('local', 'test -t 0; echo "tty=$?"; id -un');

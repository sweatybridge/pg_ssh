-- No-network verification of the pg_ssh catalog + privilege model.
-- Run against a cluster that has the extension installed:
--   psql -p <port> -d pg_ssh -1 -f verify.sql
\set ON_ERROR_STOP 0

\echo '== 1. schema + catalog table exist =='
SELECT to_regclass('ssh.hosts') AS hosts_table_exists;   -- expect t

\echo '== 2. catalog columns =='
SELECT column_name, is_nullable, column_default
  FROM information_schema.columns
 WHERE table_schema = 'ssh' AND table_name = 'hosts'
 ORDER BY ordinal_position;

\echo '== 3. ssh_exec lives in schema ssh and is SECURITY DEFINER =='
SELECT pronamespace::regnamespace::text AS nsp, proname, prosecdef AS security_definer
  FROM pg_proc
 WHERE proname = 'ssh_exec';

\echo '== 4. PUBLIC has NO direct access to the credential table =='
SELECT has_table_privilege('public', 'ssh.hosts', 'SELECT') AS public_can_select;  -- expect f

\echo '== 5. an unregistered host_name raises (catalog lookup path works) =='
SELECT * FROM ssh.ssh_exec('definitely-not-registered', 'true');  -- expect ERROR

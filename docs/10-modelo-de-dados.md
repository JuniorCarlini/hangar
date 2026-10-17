# 10 — Modelo de dados (SQLite do painel)

Convenções: IDs são ULID em texto; datas em UTC, ISO-8601 (`TEXT`);
`*_enc` = BLOB cifrado (ver [04](04-seguranca.md)); `PRAGMA foreign_keys=ON`,
`journal_mode=WAL`, `busy_timeout=5000`.

```sql
-- Usuários e acesso
users            (id, email UNIQUE, password_hash, role CHECK(role IN ('owner','admin','viewer')),
                  totp_secret_enc, failed_logins, locked_at, created_at, updated_at)
webauthn_creds   (id, user_id → users, credential_id UNIQUE, public_key, sign_count, name, created_at, last_used_at)
recovery_codes   (id, user_id → users, code_hash, used_at)
sessions         (id_hash PRIMARY KEY, user_id → users, ip, user_agent, created_at,
                  last_seen_at, expires_at, sudo_until)

-- Recursos
servers          (id, name, role, wg_ip NULL, labels_json, agent_cert_fingerprint NULL,
                  status, last_seen_at, created_at)            -- MVP: uma linha 'local'
projects         (id, slug UNIQUE, name, network_id, created_at)
services         (id, project_id → projects, server_id → servers, slug, kind CHECK(kind IN ('app','template')),
                  replicas DEFAULT 1, singleton BOOLEAN, stateful BOOLEAN, placement_labels_json,
                  template_id, template_version, source_type, source_ref,      -- imagem ou repo/branch
                  git_token_enc, registry_auth_enc, dockerfile_path,
                  memory_bytes, nano_cpus, pids_limit, read_only, healthcheck_json,
                  pre_deploy_cmd, internal_port, accepts_dynamic_domains BOOLEAN,
                  webhook_token_hash, current_deployment_id, created_at, updated_at,
                  UNIQUE(project_id, slug))
env_vars         (id, service_id → services, key, value_enc, secret BOOLEAN, UNIQUE(service_id, key))
volumes          (id, service_id → services, name UNIQUE, mount_path, size_bytes, measured_at)
port_exposures   (id, service_id → services, host_port, container_port, protocol,
                  access CHECK(access IN ('any','cidrs','localhost')), allowed_cidrs,
                  expires_at NULL, created_by, created_at)
project_links    (project_a → projects, project_b → projects, created_by, created_at,
                  PRIMARY KEY(project_a, project_b), CHECK(project_a < project_b))

-- Deploys
deployments      (id, service_id → services, status, trigger, commit_sha, commit_message, image_ref, image_digest,
                  container_id, log_path, error, started_at, finished_at, created_by)
-- Build por Git (Etapa 10): a fonte fica numa tabela à parte, não em services
service_git      (service_id PRIMARY KEY → services, repo_url, branch, subdir, dockerfile,
                  token_enc, webhook_token_hash UNIQUE, webhook_token_enc, webhook_secret_enc, updated_at)
webhook_deliveries (delivery_id PRIMARY KEY, service_id → services, received_at)   -- anti-replay, 7 dias

-- Domínios e TLS
domains          (id, service_id → services, hostname UNIQUE, kind CHECK(kind IN ('fixed','wildcard')),
                  path_prefix, redirect_to, created_at)
domain_blocklist (hostname PRIMARY KEY, reason, created_at, created_by)
tls_ask_log      (hostname, decision, reason, hour, count, last_at,              -- agregado por hora,
                  PRIMARY KEY(hostname, decision, hour))                        -- retenção 30 dias ([20])
app_check_config (service_id PRIMARY KEY → services, path, hmac_secret_enc, timeout_ms)

-- Operação
metrics          (container_key, resolution CHECK(resolution IN ('1m','1h')), ts,
                  cpu_pct, mem_bytes, mem_limit, net_rx, net_tx, blk_read, blk_write,
                  PRIMARY KEY(container_key, resolution, ts)) WITHOUT ROWID
backup_recipients (id, label, age_public_key, pgp_public_key, confirmed_at, created_at)  -- nunca chave privada
backup_targets   (id, kind, config_enc, object_lock_days, is_primary, created_at)
backup_policies  (id, service_id → services, target_id → backup_targets, schedule, retention_json)
backup_runs      (id, policy_id → backup_policies, kind CHECK(kind IN ('pg_dump','pg_base','redis','volume','panel','bucket_sync')),
                  status, object_key, size_bytes, sha256, verified BOOLEAN, error, started_at, finished_at)
wal_status       (service_id PRIMARY KEY → services, last_archived_wal, last_archived_at, lag_seconds)
alert_channels   (id, kind CHECK(kind IN ('telegram','email','webhook')), name, target,  -- target: resumo sem segredo
                  min_severity, enabled, config_enc, created_by, created_at, updated_at)
alert_rules      (kind PRIMARY KEY, enabled, threshold, updated_at)  -- regras do servidor; sem linha = padrão
alerts           (id INTEGER PRIMARY KEY, kind, severity, category CHECK(category IN ('server','security')),
                  dedup_key, params_json, resolved, muted, repeats, created_at, last_at)       -- 90 dias ([20])
alert_deliveries (id INTEGER PRIMARY KEY, alert_id → alerts, channel_id → alert_channels, channel_name,
                  channel_kind, kind, status CHECK(status IN ('sent','failed','dropped')),
                  attempts, error, created_at)                                               -- 30 dias ([20])
alert_seen       (user_id PRIMARY KEY → users, last_id)    -- ponto vermelho do sino
login_ips        (user_id → users, ip, first_at, last_at, PRIMARY KEY(user_id, ip))  -- "login de IP novo"
backup_recipients (id, label, age_public_key UNIQUE, confirm_hash, confirmed_at, created_by, created_at)  -- nunca chave privada
backup_targets   (id, name, provider, config_enc, lock_mode, object_lock_days, is_primary, checked_at, check_error, created_at)
backup_policies  (id, service_id NULL → services (NULL = o painel), enabled, every_hours, at_minute, wal, wal_since, next_run_at)
backup_runs      (id, service_id, label, kind CHECK(kind IN ('pg_dump','pg_base','redis','volume','panel','bucket_sync')),
                  trigger, class, status, object_key, size_bytes, sha256, verified, check_json, uploads_json, warning, error,
                  started_at, finished_at)
wal_status       (service_id PRIMARY KEY → services, last_archived_wal, last_archived_at, pending, oldest_pending_at, last_error)
backup_restores  (id, service_id, label, mode CHECK(mode IN ('pitr','dump')), point, destination, new_service,
                  status, step, error, created_by, started_at, finished_at)
alert_channels   (id, kind, config_enc)
alert_rules      (id, kind, params_json, channel_id → alert_channels, enabled)

-- Atualizações e vulnerabilidades
sboms            (deployment_id PRIMARY KEY → deployments, format, content_zstd, created_at)
dependency_findings (id, service_id → services, ecosystem, package, current_version, latest_version,
                  fixed_version, severity, advisory_id, kind CHECK(kind IN ('vuln','patch','minor','major')),
                  first_seen_at, last_seen_at, resolved_at, notified_at)
finding_ignores  (id, service_id, package, advisory_id NULL, until_version NULL, until_at NULL,
                  reason, created_by, created_at)

-- Link público de status
status_links     (id, name, token_hash UNIQUE, naming CHECK(naming IN ('alias','generic','hidden')),
                  service_ids_json, password_hash NULL, allowed_cidrs NULL, expires_at NULL,
                  revoked_at NULL, created_by, created_at, last_access_at, access_count)
service_aliases  (service_id PRIMARY KEY → services, public_label)

-- Auditoria (append-only; trigger impede UPDATE/DELETE)
audit_log        (id INTEGER PRIMARY KEY, ts, user_id, ip, user_agent, action, target_type,
                  target_id, summary_json, prev_hash, hash)
settings         (key PRIMARY KEY, value_json)
```

Regras:

- Volume e retenção de cada tabela seguem [20](20-logs-e-retencao.md):
  nada de log de alto volume no SQLite.

- Migrações só para frente, embutidas no binário, aplicadas no boot dentro de
  transação. Backup automático do banco antes de qualquer migração.
- Estado do Docker não é duplicado sem necessidade: o SQLite guarda a
  **intenção**; um *reconciliador* (a cada 30 s e em eventos do Docker)
  compara com a realidade e corrige/alerta.

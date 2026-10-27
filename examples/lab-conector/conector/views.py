"""One page that shows which variables reached the app and whether Postgres
and Redis answer through them. Every visit writes to both, so a working
page proves the connection end to end."""

import html
import os

import psycopg
import redis
from django.http import HttpResponse

# The names this app reads. They differ on purpose from what the Postgres
# and Redis templates offer (HOST, PASSWORD, REDIS_URL…): the connector
# bridges each one.
DB_VARS = ["DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASS"]
CACHE_VARS = ["CACHE_URL"]
SECRET_VARS = {"DB_PASS", "CACHE_URL"}


def check_postgres():
    missing = [k for k in DB_VARS if not os.environ.get(k)]
    if missing:
        return False, "faltam " + ", ".join(missing)
    try:
        with psycopg.connect(
            host=os.environ["DB_HOST"],
            port=os.environ["DB_PORT"],
            dbname=os.environ["DB_NAME"],
            user=os.environ["DB_USER"],
            password=os.environ["DB_PASS"],
            connect_timeout=3,
        ) as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS visitas (em timestamptz NOT NULL DEFAULT now())")
            conn.execute("INSERT INTO visitas DEFAULT VALUES")
            total = conn.execute("SELECT count(*) FROM visitas").fetchone()[0]
            version = conn.execute("SHOW server_version").fetchone()[0]
        return True, f"Postgres {version} · {total} visitas gravadas"
    except Exception as e:  # noqa: BLE001 — the page shows any failure
        return False, str(e).strip().splitlines()[0]


def check_redis():
    url = os.environ.get("CACHE_URL")
    if not url:
        return False, "falta CACHE_URL"
    try:
        r = redis.Redis.from_url(url, socket_timeout=3, socket_connect_timeout=3)
        total = r.incr("visitas")
        version = r.info("server").get("redis_version", "?")
        return True, f"Redis {version} · contador em {total}"
    except Exception as e:  # noqa: BLE001
        return False, str(e).strip().splitlines()[0]


def shown(key):
    v = os.environ.get(key)
    if not v:
        return '<span class="no">não chegou</span>'
    if key in SECRET_VARS:
        return '<span class="ok">chegou</span> <code>••••••</code>'
    return f'<span class="ok">chegou</span> <code>{html.escape(v)}</code>'


def card(title, ok, detail, keys):
    rows = "".join(f"<tr><td><code>{k}</code></td><td>{shown(k)}</td></tr>" for k in keys)
    state = "conectado" if ok else "sem conexão"
    return (
        f'<section class="{"ok" if ok else "no"}"><h2>{title} <small>{state}</small></h2>'
        f"<p>{html.escape(detail)}</p><table>{rows}</table></section>"
    )


PAGE = """<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Lab conector</title>
<style>
body{{margin:0;font:15px/1.5 system-ui,sans-serif;background:#0e1014;color:#e8eaed}}
main{{max-width:720px;margin:0 auto;padding:32px 16px;display:grid;gap:16px}}
h1{{margin:0;font-size:22px}} p{{margin:4px 0 12px;color:#9aa2ae}}
section{{border:1px solid #262b33;border-left-width:4px;border-radius:6px;padding:16px;background:#13161b}}
section.ok{{border-left-color:#3dd68c}} section.no{{border-left-color:#ff6369}}
h2{{margin:0;font-size:16px}} small{{font-weight:400;color:#9aa2ae;margin-left:6px}}
table{{width:100%;border-collapse:collapse}} td{{padding:6px 0;border-top:1px solid #262b33}}
code{{font:13px ui-monospace,Menlo,monospace}} .ok{{color:#3dd68c}} .no{{color:#ff6369}}
</style></head><body><main>
<h1>Lab conector</h1>
<p>Esta app lê nomes próprios. Ligue cada um no conector do Hangar.</p>
{postgres}{redis}
</main></body></html>"""


def home(request):
    pg_ok, pg_detail = check_postgres()
    rd_ok, rd_detail = check_redis()
    body = PAGE.format(
        postgres=card("Postgres", pg_ok, pg_detail, DB_VARS),
        redis=card("Redis", rd_ok, rd_detail, CACHE_VARS),
    )
    return HttpResponse(body)


def healthz(request):
    return HttpResponse("ok", content_type="text/plain")

#!/usr/bin/env python3
"""Retool Upgrade Report collector.

Read-only. Works with Kubernetes (Helm), Docker Compose, or plain Docker.
Gathers deployment + usage facts into ONE JSON file you can inspect before
sending to Retool. Secrets are never written: env var values are kept only for
an explicit allowlist; everything else is recorded by name only.

Interactive by default (detects your setup and asks when unsure). For scripts/CI:
  collect.py --platform kubernetes -n retool --yes
  collect.py --platform docker --compose-project retool --yes
"""
import argparse, datetime, json, os, re, shutil, subprocess, sys, uuid

if sys.version_info < (3, 7):
    sys.exit("This collector needs Python 3.7+. Found %s." % sys.version.split()[0])

SCHEMA_VERSION = 3
COLLECTOR_VERSION = "0.5.2"
BACKEND_IMAGE = "tryretool/backend"          # default image-name match; override with --image-pattern
RETOOL_IMAGE_RE = re.compile(re.escape(BACKEND_IMAGE))


def is_retool_backend(image, env_names):
    """A Retool backend-image service, even if the image was mirrored/renamed:
    match the image name, else the env fingerprint every Retool backend has."""
    if RETOOL_IMAGE_RE.search(image or ""):
        return True
    names = set(env_names or [])
    fingerprint = "DEPLOYMENT_TEMPLATE_TYPE" in names or {"LICENSE_KEY", "JWT_SECRET", "ENCRYPTION_KEY"} <= names
    # Compose env_file setups inject Retool's env into EVERY service (postgres, nginx, minio, ...).
    # Real backend-image services also always have SERVICE_TYPE, so require it.
    return fingerprint and "SERVICE_TYPE" in names


def mount_summary(mounts):
    """Counts only. Mount destination paths can embed customer domain names
    (e.g. /var/lib/https-portal/<your-domain>/domain.key), so the paths are not collected."""
    out = {"bind": 0, "volume": 0, "other": 0, "docker_socket": False}
    for m in mounts or []:
        t = m.get("Type")
        out[t if t in ("bind", "volume") else "other"] += 1
        if m.get("Destination") == "/var/run/docker.sock":
            out["docker_socket"] = True
    return out


def image_tag(image):
    """Tag of an image reference, or None. Only looks at the last path segment (registry ports contain ':')."""
    seg = (image or "").split("@")[0].rsplit("/", 1)[-1]
    return seg.split(":", 1)[1] if ":" in seg else None


def pick_backend_workload(workloads):
    """Workload to read the Retool version from: prefer the exact image match, then the MAIN_BACKEND service,
    then any flagged backend; within each group prefer one that actually has a version tag."""
    flagged = [w for w in workloads if w.get("retool_backend")]
    groups = [
        [w for w in flagged if RETOOL_IMAGE_RE.search(w["image"])],
        [w for w in flagged if "MAIN_BACKEND" in (w.get("env_values") or {}).get("SERVICE_TYPE", "")],
        flagged,
    ]
    for g in groups:  # highest-priority non-empty group wins; prefer a tagged image within it
        if g:
            return next((w for w in g if image_tag(w["image"])), None) or g[0]
    return None


# Where a Retool backend image keeps its own version (verified: /retool_backend/package.json, name "retool_backend").
VERSION_FILES = ["/retool_backend/package.json"]
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+")


def parse_backend_version(text):
    try:
        d = json.loads(text)
    except (ValueError, TypeError):
        return None
    v = d.get("version") if isinstance(d, dict) else None
    return v if isinstance(v, str) and SEMVER_RE.match(v) else None

SAFE_ENV_VALUES = {
    "DEPLOYMENT_TEMPLATE_TYPE", "DEPLOYMENT_TEMPLATE_VERSION", "NODE_ENV", "SERVICE_TYPE",
    "POSTGRES_SSL_ENABLED", "POSTGRES_PORT", "DBCONNECTOR_POSTGRES_POOL_MAX_SIZE",
    "RR_BLOB_STORAGE_PROVIDER", "RR_AGENT_PUBSUB_BACKEND", "LOG_LEVEL", "COOKIE_INSECURE",
    "RETOOLOS_SEARCH_ENABLED", "IGNORE_CODE_EXECUTOR_STARTUP_CHECK", "RETOOLOS_SLACK_INGRESS_MODE",
    "WORKFLOW_TEMPORAL_CLUSTER_NAMESPACE", "WORKFLOW_TEMPORAL_CLUSTER_FRONTEND_PORT",
    "TZ", "NODE_OPTIONS", "DISABLE_IFRAME_SANDBOX", "COOKIE_MAX_AGE", "MAX_BODY_SIZE",
}
SECRET_KEY_RE = re.compile(r"(secret|password|passwd|token|key|license|jwt|credential|private|cert)", re.I)
HOSTLIKE_RE = re.compile(r"(domain|host|url|endpoint|email|user$|bucket|accountid)", re.I)

warnings = []
INTERACTIVE = sys.stdin.isatty() and sys.stdout.isatty()


# ---------------------------------------------------------------- helpers
def say(msg=""):
    print(msg, file=sys.stderr)


def run(cmd, timeout=60, quiet=False, input_text=None):
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, input=input_text,
                           universal_newlines=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        if not quiet:
            warnings.append("%s: %s" % (cmd[0], e))
        return None
    if p.returncode != 0:
        if not quiet:
            lines = p.stderr.strip().splitlines() or ["exit %d" % p.returncode]
            # psql errors: keep just "relation X does not exist" etc. (old versions lack some tables)
            warnings.append("%s: %s" % (" ".join(cmd[:3]), lines[0][:160]))
        return None
    return p.stdout


def run_json(cmd, quiet=False):
    out = run(cmd, quiet=quiet)
    try:
        return json.loads(out) if out else None
    except ValueError:
        return None


def jsonl(out):
    rows = []
    for line in (out or "").splitlines():
        try:
            rows.append(json.loads(line))
        except ValueError:
            pass
    return rows


def redact(obj, key=""):
    if isinstance(obj, dict):
        return {k: redact(v, k) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v, key) for v in obj]
    if obj in (None, True, False) or isinstance(obj, (int, float)):
        return obj
    if SECRET_KEY_RE.search(key):
        return "<redacted>"
    if HOSTLIKE_RE.search(key):
        return "<set>" if obj else ""
    return obj


def env_summary(pairs):
    """pairs: list of (name, value|None). Names always kept; values only if allowlisted."""
    return (sorted({n for n, _ in pairs}),
            {n: v for n, v in pairs if n in SAFE_ENV_VALUES and v is not None})


def shq(s):
    return "'" + s.replace("'", "'\"'\"'") + "'"


def ask_choice(prompt, options, default=0):
    """options: list of (label, value). Returns value. Non-interactive -> default."""
    if len(options) == 1 or not INTERACTIVE:
        return options[default][1]
    say("\n" + prompt)
    for i, (label, _) in enumerate(options, 1):
        say("  %d) %s%s" % (i, label, "  [default]" if i - 1 == default else ""))
    while True:
        raw = input("> ").strip()
        if not raw:
            return options[default][1]
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return options[int(raw) - 1][1]
        say("  Enter a number 1-%d." % len(options))


def confirm(prompt, assume_yes):
    if assume_yes or not INTERACTIVE:
        return True
    return input("\n%s [Y/n] " % prompt).strip().lower() in ("", "y", "yes")


# ---------------------------------------------------------------- DB queries
# name -> (sql, tables that must exist). Missing tables => "unavailable on this version",
# which is different from "feature unused" (a null/0 value).
DB_QUERIES = {
    "postgres_version": ("select version()", []),
    "migrations": ("select count(*)||' / latest '||max(name) from \"SequelizeMeta\"", ["SequelizeMeta"]),
    "app_count": ("select count(*) from pages where \"deletedAt\" is null", ["pages"]),
    "user_count": ("select count(*) from users", ["users"]),
    "group_count": ("select count(*) from groups", ["groups"]),
    "environment_count": ("select count(*) from environments", ["environments"]),
    "environment_config_vars": ("select count(*) from environment_config_vars", ["environment_config_vars"]),
    "apps_new_app_builder": ("select count(*) from pages where \"deletedAt\" is null and \"isReactApp\"", ["pages.isReactApp"]),
    "apps_mobile": ("select count(*) from pages where \"deletedAt\" is null and \"isMobileApp\"", ["pages.isMobileApp"]),
    "apps_modules": ("select count(*) from pages where \"deletedAt\" is null and \"isGlobalWidget\"", ["pages.isGlobalWidget"]),
    "apps_protected": ("select count(*) from pages where \"deletedAt\" is null and \"protected\"", ["pages.protected"]),
    "apps_source_controlled": ("select count(*) from pages where \"deletedAt\" is null and \"sourceControlUuid\" is not null", ["pages.sourceControlUuid"]),
    "app_builder_repos": ("select count(*) from rr_app_repos where \"deletedAt\" is null", ["rr_app_repos"]),
    "app_builder_function_approvals": ("select count(*) from rr_serverless_function_approvals", ["rr_serverless_function_approvals"]),
    "automation_functions": ("select count(*) from aa_functions", ["aa_functions"]),
    "automation_triggers_by_type": ("select coalesce(json_object_agg(type, n), '{}') from (select type, count(*) n from aa_triggers group by 1) t", ["aa_triggers"]),
    "workflow_count": ("select count(*) from workflow", ["workflow"]),
    "workflow_triggers_by_type": ("select coalesce(json_object_agg(\"triggerType\", n), '{}') from (select \"triggerType\", count(*) n from workflow_trigger group by 1) t", ["workflow_trigger"]),
    "workflow_library_packages": ("select count(*) from rr_library_packages", ["rr_library_packages"]),
    "resource_types": ("select coalesce(json_object_agg(type, n), '{}') from "
                       "(select type, count(*) n from resources group by 1) t", ["resources"]),
    "custom_component_collections": ("select count(*) from custom_component_collections", ["custom_component_collections"]),
    "source_control_providers": ("select count(*) from source_control_provider_configs", ["source_control_provider_configs"]),
    "embeds": ("select count(*) from embeds", ["embeds"]),
    "external_embed_sessions": ("select count(*) from external_embed_sessions", ["external_embed_sessions"]),
    "api_keys": ("select count(*) from api_keys", ["api_keys"]),
    "personal_access_tokens_active": ("select count(*) from personal_access_tokens where not revoked", ["personal_access_tokens.revoked"]),
    "agents": ("select count(*) from agents", ["agents"]),
    "retoolos_agents": ("select count(*) from retoolos_agents", ["retoolos_agents"]),
}
# Org flags: output key -> (column, kind). Only columns that exist are selected; kind "present"
# reports whether a sensitive column is set instead of its contents.
ORG_FLAG_COLUMNS = {
    "sso_type": ("customSSOType", "value"), "has_saml_idp": ("idpMetadataXML", "present"),
    "two_factor_required": ("twoFactorAuthRequired", "value"), "jit_enabled": ("jitEnabled", "value"),
    "release_management": ("releaseManagementEnabled", "value"), "git_configured": ("gitUrl", "present"),
    "permissions_v2_custom_groups_migrated": ("permissionsV2CustomGroupsMigrated", "value"),
    "plan_id": ("planId", "value"),
}
PSQL = ('export PGPASSWORD="$POSTGRES_PASSWORD"; '
        'psql -U "${POSTGRES_USER:-postgres}" -d "${POSTGRES_DB:-hammerhead_production}" '
        '-At -v ON_ERROR_STOP=1 -c "$SQL"')


def _psql(exec_prefix, sql):
    val = run(exec_prefix + ["SQL=%s; %s" % (shq(sql), PSQL)])
    if val is None:
        return None, True
    val = val.strip()
    try:
        return json.loads(val), False
    except ValueError:
        return val, False


def run_db_queries(exec_prefix):
    """exec_prefix: argv that runs `sh -c <script>` inside the postgres container/pod.
    Returns {"values": {...}, "unavailable": {name: reason}, "errors": [names]}."""
    out = {"values": {}, "unavailable": {}, "errors": []}
    tables, err = _psql(exec_prefix, "select string_agg(table_name, ',') from information_schema.tables "
                                     "where table_schema='public'")
    if err or not tables:
        out["errors"].append("table_discovery (is this the Retool database?)")
        return out
    have = set(tables.split(","))
    col_tables = sorted({n.split(".")[0] for _, needs in DB_QUERIES.values() for n in needs if "." in n})
    cols_raw, _ = _psql(exec_prefix, "select string_agg(table_name||'.'||column_name, ',') from information_schema.columns "
                                     "where table_schema='public' and table_name in (%s)"
                        % ",".join("'%s'" % t for t in col_tables))
    have_cols = set((cols_raw or "").split(","))
    for name, (sql, needs) in DB_QUERIES.items():
        missing = [n for n in needs if (n not in have_cols if "." in n else n not in have)]
        if missing:
            out["unavailable"][name] = "missing: " + ",".join(missing)
            continue
        val, err = _psql(exec_prefix, sql)
        if err:
            out["errors"].append(name)
        else:
            out["values"][name] = val
    if "organizations" in have:
        cols, _ = _psql(exec_prefix, "select string_agg(column_name, ',') from information_schema.columns "
                                     "where table_name='organizations'")
        cols = set((cols or "").split(","))
        parts, absent = [], []
        for key, (col, kind) in ORG_FLAG_COLUMNS.items():
            if col not in cols:
                absent.append(key)
            else:
                expr = '"%s" is not null' % col if kind == "present" else '"%s"' % col
                parts.append("'%s', %s" % (key, expr))
        if parts:
            val, err = _psql(exec_prefix, "select json_build_object(%s) from organizations order by id limit 1"
                             % ",".join(parts))
            if err:
                out["errors"].append("org_flags")
            else:
                out["values"]["org_flags"] = val
        if absent:
            out["unavailable"]["org_flags_missing_columns"] = absent
    else:
        out["unavailable"]["org_flags"] = "table missing: organizations"
    return out


def write_sql_file(path):
    with open(path, "w") as f:
        f.write("-- Run against your Retool database (read-only queries). Send the output to Retool.\n")
        for name, (sql, _) in DB_QUERIES.items():
            f.write("-- %s\n%s;\n\n" % (name, sql))


# ---------------------------------------------------------------- Kubernetes
class Kubernetes:
    name = "kubernetes"

    def read_backend_version(self, w):
        target = ("statefulset/" if w.get("kind") == "StatefulSet" else "deploy/") + w["name"]
        for path in VERSION_FILES:
            v = parse_backend_version(run(["kubectl", "exec", "-n", self.ns, target, "--", "cat", path], quiet=True))
            if v:
                return v
        return None

    def __init__(self, ns, release):
        self.ns, self.release = ns, release

    @staticmethod
    def tools():
        return [t for t in ("kubectl", "helm") if shutil.which(t)]

    @staticmethod
    def context():
        out = run(["kubectl", "config", "current-context"], quiet=True)
        return out.strip() if out else None

    @staticmethod
    def find_namespaces():
        """Namespaces that contain Retool backend deployments."""
        data = run_json(["kubectl", "get", "deploy", "-A", "-o", "json"], quiet=True)
        found = set()
        for it in (data or {}).get("items", []):
            for c in it["spec"]["template"]["spec"].get("containers", []):
                if is_retool_backend(c["image"], [e["name"] for e in (c.get("env") or [])]):
                    found.add(it["metadata"]["namespace"])
        return sorted(found)

    def preflight(self):
        checks = []
        ok = run(["kubectl", "get", "deploy", "-n", self.ns], quiet=True) is not None
        checks.append((ok, "kubectl can list deployments in namespace '%s'" % self.ns))
        can_exec = run(["kubectl", "auth", "can-i", "create", "pods/exec", "-n", self.ns], quiet=True)
        checks.append((bool(can_exec and can_exec.strip() == "yes"),
                       "kubectl can exec into pods (needed only for the database step)"))
        checks.append((shutil.which("helm") is not None, "helm installed (optional: adds chart/values info)"))
        if not SKIP_PLAN:
            checks.append((reachable(HELM_REPO + "/index.yaml"),
                           "can reach charts.retool.com (optional: needed for the upgrade plan; use --skip-plan to skip it)"))
        return checks

    def collect(self, skip_db, postgres_target):
        ns = self.ns
        workloads = self._workloads()
        report = {
            "helm": self._helm() if shutil.which("helm") else {"skipped": "helm not installed"},
            "cluster": self._cluster(),
            "workloads": workloads,
            "pod_health": self._pods(),
        }
        if skip_db:
            return report, workloads
        pod = postgres_target
        if not pod:
            pods = run(["kubectl", "get", "pods", "-n", ns, "-o", "name"], quiet=True) or ""
            pod = next((p.split("/")[1] for p in pods.split() if "postgresql" in p), None)
        report["database"] = (run_db_queries(["kubectl", "exec", "-n", ns, pod, "--", "sh", "-c"])
                              if pod else {"skipped": "no bundled postgres pod; external DB? use --emit-sql"})
        return report, workloads

    def _helm(self):
        out = {}
        rel = run_json(["helm", "list", "-n", self.ns, "-o", "json"]) or []
        match = [r for r in rel if not self.release or r["name"] == self.release]
        if match:
            name = match[0]["name"]
            out["release"] = match[0]
            out["user_supplied_values"] = redact(run_json(["helm", "get", "values", name, "-n", self.ns, "-o", "json"]))
            hist = run_json(["helm", "history", name, "-n", self.ns, "-o", "json"]) or []
            out["history"] = [{k: h.get(k) for k in ("revision", "updated", "status", "chart")} for h in hist]
        else:
            warnings.append("no helm release found in namespace %s" % self.ns)
        return out

    def _workloads(self):
        items = []
        for kind in ("deployments", "statefulsets", "daemonsets"):
            data = run_json(["kubectl", "get", kind, "-n", self.ns, "-o", "json"]) or {"items": []}
            for it in data["items"]:
                spec = it["spec"]["template"]["spec"]
                for c in spec.get("containers", []):
                    names, vals = env_summary([(e["name"], e.get("value")) for e in c.get("env", []) or []])
                    items.append({
                        "kind": it["kind"], "name": it["metadata"]["name"], "container": c["name"],
                        "image": c["image"], "replicas": it["spec"].get("replicas"),
                        "ready": it.get("status", {}).get("readyReplicas"),
                        "resources": c.get("resources", {}),
                        "env_var_names": names, "env_values": vals,
                        "retool_backend": is_retool_backend(c["image"], names),
                        "node_selector": spec.get("nodeSelector"),
                    })
        return items

    def _pods(self):
        data = run_json(["kubectl", "get", "pods", "-n", self.ns, "-o", "json"]) or {"items": []}
        out = []
        for p in data["items"]:
            for cs in p.get("status", {}).get("containerStatuses", []) or []:
                last = (cs.get("lastState") or {}).get("terminated") or {}
                out.append({"pod": p["metadata"]["name"], "container": cs["name"],
                            "restarts": cs.get("restartCount", 0), "ready": cs.get("ready"),
                            "last_termination_reason": last.get("reason")})
        return out

    def _cluster(self):
        ver = run_json(["kubectl", "version", "-o", "json"]) or {}
        nodes = run_json(["kubectl", "get", "nodes", "-o", "json"]) or {"items": []}
        ing = run_json(["kubectl", "get", "ingress", "-n", self.ns, "-o", "json"]) or {"items": []}
        pvc = run_json(["kubectl", "get", "pvc", "-n", self.ns, "-o", "json"]) or {"items": []}
        return {
            "kubernetes_server_version": (ver.get("serverVersion") or {}).get("gitVersion"),
            "nodes": [{"kubelet": n["status"]["nodeInfo"]["kubeletVersion"],
                       "os": n["status"]["nodeInfo"]["osImage"],
                       "arch": n["status"]["nodeInfo"]["architecture"],
                       "cpu": n["status"]["capacity"]["cpu"], "memory": n["status"]["capacity"]["memory"]}
                      for n in nodes["items"]],
            "ingress": [{"class": i["spec"].get("ingressClassName"), "tls": bool(i["spec"].get("tls"))}
                        for i in ing["items"]],
            "pvcs": [{"storage_class": p["spec"].get("storageClassName"),
                      "size": p["spec"]["resources"]["requests"].get("storage")} for p in pvc["items"]],
        }


# ---------------------------------------------------------------- Docker / Compose
class Docker:
    def read_backend_version(self, w):
        for path in VERSION_FILES:
            v = parse_backend_version(run(["docker", "exec", w["container"], "cat", path], quiet=True))
            if v:
                return v
        return None

    def __init__(self, project):
        self.project = project  # compose project name, or None for "all retool containers"
        self.name = "docker-compose" if project else "docker"

    @staticmethod
    def tools():
        return ["docker"] if shutil.which("docker") else []

    @staticmethod
    def available():
        return run(["docker", "info", "--format", "{{.ServerVersion}}"], quiet=True) is not None

    @staticmethod
    def _inspect_all():
        ids = (run(["docker", "ps", "-aq"], quiet=True) or "").split()
        if not ids:
            return []
        return run_json(["docker", "inspect"] + ids, quiet=True) or []

    @staticmethod
    def find_projects():
        """Compose projects (or '' for non-compose) that contain a Retool backend container."""
        found = set()
        for c in Docker._inspect_all():
            env_names = [e.split("=", 1)[0] for e in (c["Config"].get("Env") or [])]
            if is_retool_backend(c["Config"]["Image"], env_names):
                found.add((c["Config"].get("Labels") or {}).get("com.docker.compose.project", ""))
        return sorted(found)

    def preflight(self):
        return [
            (Docker.available(), "docker daemon reachable (is it running? do you need sudo / docker group?)"),
            (run(["docker", "compose", "version"], quiet=True) is not None, "docker compose plugin (optional)"),
        ] + ([] if SKIP_PLAN else [(reachable(COMPOSE_REF_URL),
                                    "can reach github.com (optional: needed for the upgrade plan; use --skip-plan to skip it)")])

    def _containers(self):
        out = []
        for c in Docker._inspect_all():
            labels = c["Config"].get("Labels") or {}
            if self.project:  # a compose project: everything in it (backend, postgres, temporal, ...)
                if labels.get("com.docker.compose.project") == self.project:
                    out.append(c)
            elif ("tryretool" in c["Config"]["Image"] or
                  is_retool_backend(c["Config"]["Image"], [e.split("=", 1)[0] for e in (c["Config"].get("Env") or [])])):
                out.append(c)  # plain docker: Retool images / backend-fingerprint containers only
        if self.project:
            # Short-lived containers that Retool itself launches (e.g. agent sandbox jobs) carry the project label but
            # none of Compose's own metadata. If the real services have it, drop the ones that don't.
            meta = "com.docker.compose.project.config_files"
            if any((c["Config"].get("Labels") or {}).get(meta) for c in out):
                out = [c for c in out if (c["Config"].get("Labels") or {}).get(meta)]
        return out

    def collect(self, skip_db, postgres_target):
        containers = self._containers()
        workloads, health = [], []
        for c in containers:
            env = []
            for e in c["Config"].get("Env") or []:
                k, _, v = e.partition("=")
                env.append((k, v))
            names, vals = env_summary(env)
            hc = c["HostConfig"]
            labels = c["Config"].get("Labels") or {}
            workloads.append({
                "kind": "container",
                "name": labels.get("com.docker.compose.service") or c["Name"].lstrip("/"),
                "container": c["Name"].lstrip("/"),
                "image": c["Config"]["Image"],
                "replicas": 1, "ready": 1 if c["State"].get("Running") else 0,
                "resources": {"memory_limit_bytes": hc.get("Memory") or None,
                              "nano_cpus": hc.get("NanoCpus") or None},
                "env_var_names": names, "env_values": vals,
                "retool_backend": is_retool_backend(c["Config"]["Image"], names),
                "ports": sorted((c["NetworkSettings"].get("Ports") or {}).keys()),
                "restart_policy": (hc.get("RestartPolicy") or {}).get("Name"),
                "mounts": mount_summary(c.get("Mounts", [])),
                # basenames only: the full host path contains usernames/repo names
                "compose_config_files": ",".join(os.path.basename(p) for p in
                                                 (labels.get("com.docker.compose.project.config_files") or "").split(",") if p) or None,
            })
            health.append({"container": c["Name"].lstrip("/"), "status": c["State"].get("Status"),
                           "restarts": c.get("RestartCount", 0), "oom_killed": c["State"].get("OOMKilled"),
                           "exit_code": c["State"].get("ExitCode"),
                           "health": (c["State"].get("Health") or {}).get("Status")})
        info = run_json(["docker", "info", "--format", "{{json .}}"]) or {}
        comp = run(["docker", "compose", "version", "--short"], quiet=True)
        report = {
            "host": {"docker_server_version": info.get("ServerVersion"),
                     "compose_version": comp.strip() if comp else None,
                     "os": info.get("OperatingSystem"), "arch": info.get("Architecture"),
                     "cpus": info.get("NCPU"), "memory_bytes": info.get("MemTotal")},
            "workloads": workloads, "container_health": health,
        }
        if skip_db:
            return report, workloads
        pg = postgres_target or next((w["container"] for w in workloads
                                      if re.search(r"postgres", w["image"]) and "temporal" not in w["image"]), None)
        report["database"] = (run_db_queries(["docker", "exec", pg, "sh", "-c"]) if pg else
                              {"skipped": "no postgres container found (external DB?). use --emit-sql"})
        return report, workloads


# ---------------------------------------------------------------- main flow
# ---------------------------------------------------------------- upgrade plan: what comes with the new version, and is there room?
HELM_REPO = "https://charts.retool.com"
COMPOSE_REF_URL = "https://raw.githubusercontent.com/tryretool/retool-onpremise/master/compose.yaml"

SKIP_PLAN = False


def reachable(url, timeout=8):
    """True if the URL answers (honours HTTP(S)_PROXY). Used only for the optional upgrade-plan preflight."""
    try:
        import urllib.request
        urllib.request.urlopen(urllib.request.Request(url, method="GET"), timeout=timeout).close()
        return True
    except Exception:
        return False


# Typical sizing of Retool services: the default resource REQUESTS in Retool's public Helm chart (chart 6.13.x).
# aliases = the service's name in Helm and in the official docker-compose file.
SIZING = [
    {"role": "Main backend",              "aliases": ["api", "main-retool"],                                    "cpu_m": 500,  "mem_mi": 1024},
    {"role": "Workflows backend",         "aliases": ["workflows-backend", "workflow-backend"],                 "cpu_m": 256,  "mem_mi": 512},
    {"role": "Workflows worker",          "aliases": ["workflows-worker", "workflow-worker"],                   "cpu_m": 256,  "mem_mi": 512},
    {"role": "Jobs runner",               "aliases": ["jobs-runner"],                                           "cpu_m": 256,  "mem_mi": 512, "estimate": True},
    {"role": "Agent worker",              "aliases": ["r2-agent-worker", "agent-worker", "agent-eval-worker"],  "cpu_m": 1000, "mem_mi": 2048},
    {"role": "Retool OS agent worker",    "aliases": ["retoolos-temporal-worker"],                              "cpu_m": 1000, "mem_mi": 2048},
    {"role": "Code Executor",             "aliases": ["code-executor"],                                         "cpu_m": 1000, "mem_mi": 1024},
    {"role": "JS Executor",               "aliases": ["js-executor"],                                           "cpu_m": 2000, "mem_mi": 6144},
    {"role": "Agent sandbox controller",  "aliases": ["agent-sandbox-controller"],                              "cpu_m": 250,  "mem_mi": 256},
    {"role": "Agent sandbox proxy",       "aliases": ["agent-sandbox-proxy"],                                   "cpu_m": 250,  "mem_mi": 256},
    {"role": "MCP server",                "aliases": ["mcp"],                                                   "cpu_m": 200,  "mem_mi": 256},
    {"role": "Telemetry",                 "aliases": ["telemetry"],                                             "cpu_m": 128,  "mem_mi": 128},
]
# compose services that are infrastructure, not Retool services you'd be "adding"
COMPOSE_INFRA = {"minio", "minio-init", "postgres", "retooldb-postgres", "https-portal", "temporal"}


def sizing_for(name):
    for s in SIZING:
        if name in s["aliases"]:
            return s
    return None


def cpu_to_m(v):
    if v is None:
        return 0
    v = str(v)
    return int(float(v[:-1])) if v.endswith("m") else int(float(v) * 1000)


_MEM_UNITS = {"": 1 / 1048576, "B": 1 / 1048576, "Ki": 1 / 1024, "KiB": 1 / 1024, "Mi": 1, "MiB": 1, "Gi": 1024, "GiB": 1024,
              "Ti": 1048576, "TiB": 1048576, "K": 1000 / 1048576, "kB": 1000 / 1048576, "M": 1e6 / 1048576, "MB": 1e6 / 1048576,
              "G": 1e9 / 1048576, "GB": 1e9 / 1048576}


def mem_to_mi(v):
    m = re.match(r"^\s*([\d.]+)\s*([A-Za-z]*)\s*$", str(v)) if v is not None else None
    return int(float(m.group(1)) * _MEM_UNITS.get(m.group(2), 1)) if m else 0


def assess_fit(free_cpu_m, free_mem_mi, total_cpu_m, total_mem_mi, need_cpu_m, need_mem_mi, unknown):
    """verdict: nothing_new | fits | tight | does_not_fit | unknown_sizing"""
    out = {"need_cpu_m": need_cpu_m, "need_mem_mi": need_mem_mi, "free_cpu_m": int(free_cpu_m), "free_mem_mi": int(free_mem_mi),
           "free_after_cpu_m": int(free_cpu_m - need_cpu_m), "free_after_mem_mi": int(free_mem_mi - need_mem_mi)}
    if need_cpu_m <= 0 and need_mem_mi <= 0 and not unknown:
        out["verdict"] = "nothing_new"
    elif out["free_after_cpu_m"] < 0 or out["free_after_mem_mi"] < 0:
        out["verdict"] = "does_not_fit"
    elif unknown:
        out["verdict"] = "unknown_sizing"
    elif (total_cpu_m and out["free_after_cpu_m"] < 0.20 * total_cpu_m) or (total_mem_mi and out["free_after_mem_mi"] < 0.20 * total_mem_mi):
        out["verdict"] = "tight"
    else:
        out["verdict"] = "fits"
    return out


# --- Kubernetes / Helm
def yaml_to_objects(yaml_text):
    """YAML manifests -> JSON objects, using kubectl's client-side parser (no cluster changes, no PyYAML needed)."""
    out = run(["kubectl", "create", "--dry-run=client", "--validate=false", "-f", "-", "-o", "json"], input_text=yaml_text, timeout=90)
    if not out:
        return None
    dec, objs, i, out = json.JSONDecoder(), [], 0, out.strip()
    try:
        while i < len(out):
            o, j = dec.raw_decode(out, i)
            objs.extend(o["items"] if o.get("kind") == "List" else [o])
            i = j
            while i < len(out) and out[i].isspace():
                i += 1
    except ValueError:
        return None
    return objs


def workload_sizes(objs, release):
    res = {}
    for o in objs:
        if o.get("kind") not in ("Deployment", "StatefulSet", "DaemonSet"):
            continue
        spec = o["spec"]["template"]["spec"]
        cs = spec.get("containers", [])
        name = o["metadata"]["name"]
        if name.startswith(release + "-"):
            name = name[len(release) + 1:]          # drop the customer's release-name prefix
        res[name] = {
            "kind": o["kind"], "replicas": o["spec"].get("replicas", 1) if o["kind"] != "DaemonSet" else None,
            "cpu_req_m": sum(cpu_to_m(c.get("resources", {}).get("requests", {}).get("cpu")) for c in cs),
            "mem_req_mi": sum(mem_to_mi(c.get("resources", {}).get("requests", {}).get("memory")) for c in cs),
        }
    return res


def k8s_capacity():
    nodes = (run_json(["kubectl", "get", "nodes", "-o", "json"], quiet=True) or {}).get("items", [])
    pods = (run_json(["kubectl", "get", "pods", "-A", "-o", "json"], quiet=True) or {}).get("items", [])
    per = {}
    for n in nodes:
        a = n["status"]["allocatable"]
        per[n["metadata"]["name"]] = {"alloc_cpu_m": cpu_to_m(a["cpu"]), "alloc_mem_mi": mem_to_mi(a["memory"]), "req_cpu_m": 0, "req_mem_mi": 0}
    for p in pods:
        if p["status"].get("phase") not in ("Running", "Pending") or p["spec"].get("nodeName") not in per:
            continue
        for c in p["spec"]["containers"]:
            r = c.get("resources", {}).get("requests", {})
            per[p["spec"]["nodeName"]]["req_cpu_m"] += cpu_to_m(r.get("cpu"))
            per[p["spec"]["nodeName"]]["req_mem_mi"] += mem_to_mi(r.get("memory"))
    # live usage, only if metrics-server is installed
    usage = None
    top = run(["kubectl", "top", "nodes", "--no-headers"], quiet=True, timeout=20)
    if top:
        try:
            rows = [l.split() for l in top.strip().splitlines()]
            usage = {"cpu_m": sum(cpu_to_m(r[1]) for r in rows), "mem_mi": sum(mem_to_mi(r[3]) for r in rows)}
        except (IndexError, ValueError):
            usage = None
    return {"nodes": list(per.values()),   # node names intentionally not collected
            "alloc_cpu_m": sum(n["alloc_cpu_m"] for n in per.values()), "alloc_mem_mi": sum(n["alloc_mem_mi"] for n in per.values()),
            "req_cpu_m": sum(n["req_cpu_m"] for n in per.values()), "req_mem_mi": sum(n["req_mem_mi"] for n in per.values()),
            "usage": usage}


def k8s_upgrade_plan(ns, release_hint, target_chart):
    rels = run_json(["helm", "list", "-n", ns, "-o", "json"], quiet=True) or []
    rel = next((r for r in rels if not release_hint or r["name"] == release_hint), None)
    if not rel:
        warnings.append("upgrade plan skipped: no Helm release found")
        return None
    name = rel["name"]
    tv = target_chart
    if not tv or tv == "latest":
        chart = run(["helm", "show", "chart", "retool", "--repo", HELM_REPO], quiet=True, timeout=45)
        m = re.search(r"^version:\s*(\S+)", chart or "", re.M)
        if not m:
            warnings.append("upgrade plan skipped: could not reach %s to find the latest chart" % HELM_REPO)
            return None
        tv = m.group(1)
    cur_yaml = run(["helm", "get", "manifest", name, "-n", ns], quiet=True, timeout=60)
    values = run(["helm", "get", "values", name, "-n", ns, "-o", "json"], quiet=True)   # kept in memory only
    tgt_yaml = run(["helm", "template", name, "retool", "--repo", HELM_REPO, "--version", tv, "-n", ns, "-f", "-"],
                   input_text=values, quiet=True, timeout=120)
    if not (cur_yaml and values and tgt_yaml):
        warnings.append("upgrade plan skipped: could not render the chart (needs access to %s)" % HELM_REPO)
        return None
    cur_o, tgt_o = yaml_to_objects(cur_yaml), yaml_to_objects(tgt_yaml)
    if cur_o is None or tgt_o is None:
        warnings.append("upgrade plan skipped: could not read the rendered manifests")
        return None
    cur, tgt = workload_sizes(cur_o, name), workload_sizes(tgt_o, name)
    mult = lambda w: (w["replicas"] or 1)
    new = [dict(name=k, **tgt[k]) for k in sorted(set(tgt) - set(cur))]
    removed = sorted(set(cur) - set(tgt))
    changed = [{"name": k, "cpu_req_m": [cur[k]["cpu_req_m"], tgt[k]["cpu_req_m"]], "mem_req_mi": [cur[k]["mem_req_mi"], tgt[k]["mem_req_mi"]],
                "replicas": [cur[k]["replicas"], tgt[k]["replicas"]]}
               for k in sorted(set(cur) & set(tgt))
               if any(cur[k][f] != tgt[k][f] for f in ("cpu_req_m", "mem_req_mi", "replicas"))]
    tot = lambda W: (sum(w["cpu_req_m"] * mult(w) for w in W.values()), sum(w["mem_req_mi"] * mult(w) for w in W.values()))
    (cc, cm), (tc, tm) = tot(cur), tot(tgt)
    cap = k8s_capacity()
    # per-node placement check for new pods (largest first)
    free = [[n["alloc_cpu_m"] - n["req_cpu_m"], n["alloc_mem_mi"] - n["req_mem_mi"]] for n in cap["nodes"]]
    placed_all = True
    pods = sorted([(w["cpu_req_m"], w["mem_req_mi"]) for w in new for _ in range(mult(w))], reverse=True)
    for c_, m_ in pods:
        spot = next((f for f in free if f[0] >= c_ and f[1] >= m_), None)
        if spot:
            spot[0] -= c_
            spot[1] -= m_
        else:
            placed_all = False
    fit = assess_fit(cap["alloc_cpu_m"] - cap["req_cpu_m"], cap["alloc_mem_mi"] - cap["req_mem_mi"], cap["alloc_cpu_m"], cap["alloc_mem_mi"],
                     max(tc - cc, 0), max(tm - cm, 0), [])
    if not placed_all and fit["verdict"] in ("fits", "tight"):
        fit["verdict"] = "does_not_fit"
        fit["note"] = "total capacity is enough, but no single node has room for one of the new pods"
    return {"kind": "helm-chart", "current_chart": rel.get("chart", "").replace("retool-", ""), "target_chart": tv,
            "new_services": new, "removed_services": removed, "changed_services": changed,
            "totals": {"current_cpu_req_m": cc, "current_mem_req_mi": cm, "target_cpu_req_m": tc, "target_mem_req_mi": tm},
            "capacity": cap, "fit": fit, "basis": "resource requests (not live usage)" if not cap["usage"] else "resource requests; live usage also reported"}


# --- Docker / Compose
def docker_usage():
    rows = jsonl(run(["docker", "stats", "--no-stream", "--format", "{{json .}}"], quiet=True, timeout=60))
    cpu_pct = mem_mi = 0.0
    for r in rows:
        try:
            cpu_pct += float(str(r.get("CPUPerc", "0")).rstrip("%") or 0)
            mem_mi += mem_to_mi(str(r.get("MemUsage", "")).split("/")[0])
        except ValueError:
            pass
    return {"containers": len(rows), "cpu_cores_used": round(cpu_pct / 100, 2), "mem_used_mi": int(mem_mi)}


def compose_reference_services():
    try:
        import urllib.request
        txt = urllib.request.urlopen(COMPOSE_REF_URL, timeout=15).read().decode("utf-8", "replace")
    except Exception:
        return None
    names, in_services = [], False
    for line in txt.splitlines():
        if re.match(r"^services:\s*$", line):
            in_services = True
        elif in_services and re.match(r"^\S", line):
            break
        elif in_services:
            m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
            if m:
                names.append(m.group(1))
    return names or None


def docker_upgrade_plan(workloads, host):
    ref = compose_reference_services()
    if not ref:
        warnings.append("upgrade plan skipped: could not reach GitHub to read the official compose file")
        return None
    running = {w["name"] for w in workloads}
    new_names = [n for n in ref if n not in running and n not in COMPOSE_INFRA]
    new, unknown = [], []
    for n in new_names:
        s = sizing_for(n)
        if s:
            new.append({"name": n, "role": s["role"], "cpu_req_m": s["cpu_m"], "mem_req_mi": s["mem_mi"], "estimate": bool(s.get("estimate"))})
        else:
            unknown.append(n)
    use = docker_usage()
    cpus, mem = (host or {}).get("cpus") or 0, int(((host or {}).get("memory_bytes") or 0) / 1048576)
    free_cpu_m, free_mem = max(cpus * 1000 - use["cpu_cores_used"] * 1000, 0), max(mem - use["mem_used_mi"], 0)
    fit = assess_fit(free_cpu_m, free_mem, cpus * 1000, mem, sum(n["cpu_req_m"] for n in new), sum(n["mem_req_mi"] for n in new), unknown)
    return {"kind": "compose-reference", "reference": "tryretool/retool-onpremise (master)", "reference_services": ref,
            "new_services": new, "unsized_new_services": unknown, "removed_services": [],
            "capacity": {"host_cpus": cpus, "host_mem_mi": mem, "usage": use},
            "fit": fit, "basis": "live usage snapshot on this host plus typical service sizing from the Helm chart's default requests"}


def explain_no_deployment():
    say("Could not find a running Retool deployment. Here is what I checked:\n")
    # Kubernetes
    if not shutil.which("kubectl"):
        say("  Kubernetes: kubectl is not installed / not on PATH.")
    else:
        ctx = Kubernetes.context()
        if not ctx:
            say("  Kubernetes: kubectl found, but no current context is set.")
        elif run(["kubectl", "get", "ns", "-o", "name", "--request-timeout=5s"], quiet=True) is None:
            say("  Kubernetes: context '%s' is not reachable (is the cluster running?)." % ctx)
        else:
            say("  Kubernetes: context '%s' is reachable, but no Retool backend was found in any namespace." % ctx)
    # Docker
    if not shutil.which("docker"):
        say("  Docker:     docker is not installed / not on PATH.")
    elif not Docker.available():
        say("  Docker:     docker is installed but the daemon is not reachable "
            "(is Docker Desktop running? do you need sudo / the docker group?).")
    else:
        cs = Docker._inspect_all()
        running = [c for c in cs if (c.get("State") or {}).get("Running")]
        say("  Docker:     daemon reachable; %d containers (%d running), none look like a Retool backend." % (len(cs), len(running)))
        if running:
            shown = sorted({c["Config"]["Image"] for c in running})[:12]
            say("              running images: " + ", ".join(shown))
    say("\nWhat to try:\n"
        "  - Make sure Retool is running (Docker: `docker ps`; Kubernetes: `kubectl get pods -A`).\n"
        "  - If you mirror or rename Retool images, pass --image-pattern REGEX matching your backend image.\n"
        "  - Or choose explicitly: --platform docker --compose-project NAME   |   --platform kubernetes -n NAMESPACE")


def detect_platform(args):
    if args.platform:
        return args.platform
    k = bool(Kubernetes.tools()) and Kubernetes.context() and Kubernetes.find_namespaces()
    d = bool(Docker.tools()) and Docker.available() and Docker.find_projects()
    opts = []
    if k:
        opts.append(("Kubernetes (context: %s)" % Kubernetes.context(), "kubernetes"))
    if d:
        opts.append(("Docker / Docker Compose (local docker daemon)", "docker"))
    if not opts:
        explain_no_deployment()
        sys.exit(2)
    if len(opts) > 1 and not INTERACTIVE:
        say("Both Kubernetes and Docker look usable; pass --platform.")
        sys.exit(2)
    return ask_choice("Both Kubernetes and Docker look like they have Retool. Which should I collect from?", opts)


def build_platform(args):
    plat = detect_platform(args)
    if plat == "kubernetes":
        if not shutil.which("kubectl"):
            sys.exit("kubectl not found on PATH.")
        say("Using kubectl context: %s" % Kubernetes.context())
        ns = args.namespace
        if not ns:
            found = Kubernetes.find_namespaces()
            if not found:
                sys.exit("No Retool deployments found in any namespace. Pass -n NAMESPACE.")
            ns = ask_choice("Which namespace is Retool in?", [(n, n) for n in found])
        return Kubernetes(ns, args.release)
    if not shutil.which("docker"):
        sys.exit("docker not found on PATH.")
    proj = args.compose_project
    if proj is None:
        found = Docker.find_projects()
        if not found:
            sys.exit("No Retool containers found. Pass --compose-project NAME.")
        proj = ask_choice("Which Docker Compose project is Retool?",
                          [(p or "(containers not started by compose)", p) for p in found])
    return Docker(proj or None)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--platform", choices=["kubernetes", "docker"])
    ap.add_argument("-n", "--namespace", help="Kubernetes namespace")
    ap.add_argument("-r", "--release", help="Helm release name")
    ap.add_argument("--compose-project", help="Docker Compose project name ('' = all non-compose Retool containers)")
    ap.add_argument("--postgres-target", help="Postgres pod/container to run read-only queries in")
    ap.add_argument("--image-pattern", metavar="REGEX",
                    help="regex matching your Retool backend image name (default: tryretool/backend); "
                         "only needed if you mirror or rename images and auto-detection fails")
    ap.add_argument("--read-version-from-container", action="store_true",
                    help="also read the version from inside the backend container and record it as runtime_version "
                         "(done automatically when the image has no version tag)")
    ap.add_argument("--target-chart", default="latest", metavar="VERSION",
                    help="Helm chart version to plan the upgrade to (default: latest). Backward compatible, so latest is fine.")
    ap.add_argument("--skip-plan", action="store_true",
                    help="don't build the upgrade plan (new services + capacity check; needs network access to charts.retool.com / GitHub)")
    ap.add_argument("--customer-label", help="Free-text label to help Retool match this report (e.g. company name)")
    ap.add_argument("--target-version", help="Retool version you want to upgrade to")
    ap.add_argument("--skip-db", action="store_true", help="Don't run any database queries")
    ap.add_argument("--emit-sql", metavar="FILE", help="Write the DB queries to FILE to run yourself (external DB), then exit")
    ap.add_argument("-y", "--yes", action="store_true", help="Don't ask for confirmation")
    ap.add_argument("-o", "--output", default="retool-upgrade-report.json")
    a = ap.parse_args()
    if a.image_pattern:
        global RETOOL_IMAGE_RE
        RETOOL_IMAGE_RE = re.compile(a.image_pattern)

    if a.emit_sql:
        write_sql_file(a.emit_sql)
        say("Wrote %s. Run it with psql against your Retool DB and send us the output." % a.emit_sql)
        return 0

    global SKIP_PLAN
    SKIP_PLAN = a.skip_plan
    say("Retool Upgrade Report collector (read-only)\n")
    platform = build_platform(a)

    say("\nPreflight:")
    failed = False
    for ok, msg in platform.preflight():
        say("  [%s] %s" % ("ok" if ok else "!!", msg))
        failed = failed or (not ok and "optional" not in msg and "only for the database" not in msg)
    if failed:
        sys.exit("\nFix the items marked [!!] and re-run.")

    say("\nThis will collect: versions/images, resource sizing, env var NAMES (values only for a short\n"
        "safe allowlist), container/pod health, host/cluster info%s.\n"
        "It will NOT collect: secrets, license key, env values outside the allowlist, hostnames,\n"
        "app contents, user data, or logs. Nothing is sent anywhere; it only writes %s."
        % ("" if a.skip_db else ", and read-only COUNT-style DB queries", a.output))
    if not confirm("Proceed?", a.yes):
        sys.exit("Aborted.")

    say("\nCollecting from %s ..." % platform.name)
    body, workloads = platform.collect(a.skip_db, a.postgres_target)
    bw = pick_backend_workload(workloads)
    backend = bw["image"] if bw else None
    version = image_tag(backend) if backend else None
    version_source = "image_tag" if version else None
    runtime_version = None
    if bw and (not version or a.read_version_from_container):
        runtime_version = platform.read_backend_version(bw)
        if not version:
            if runtime_version:
                version, version_source = runtime_version, "container_package_json"
            else:
                warnings.append("Retool version unknown: the backend image '%s' has no version tag and the version "
                                "could not be read from inside the container." % backend)

    report = {
        "schema_version": SCHEMA_VERSION,
        "collector_version": COLLECTOR_VERSION,
        "report_id": str(uuid.uuid4()),
        "customer_label": a.customer_label,
        "collected_at": datetime.datetime.utcnow().isoformat() + "Z",
        "platform": platform.name,
        "current_version": version,
        "version_source": version_source,
        "runtime_version": runtime_version,
        "target_version": a.target_version,
    }
    report.update(body)
    if not a.skip_plan:
        say("Planning the upgrade (what the new version adds, and whether you have room) ...")
        try:
            if platform.name == "kubernetes":
                report["upgrade_plan"] = k8s_upgrade_plan(platform.ns, platform.release, a.target_chart) if shutil.which("helm") else None
                if not shutil.which("helm"):
                    warnings.append("upgrade plan skipped: helm is not installed")
            else:
                report["upgrade_plan"] = docker_upgrade_plan(workloads, report.get("host"))
        except Exception as e:   # the plan is a bonus; never let it break the report
            report["upgrade_plan"] = None
            warnings.append("upgrade plan failed: %s" % str(e)[:160])
    report["collector_warnings"] = warnings
    with open(a.output, "w") as f:
        json.dump(report, f, indent=2, sort_keys=True)

    say("\nDone: wrote %s" % a.output)
    say("  platform: %s | retool version: %s | workloads: %d | warnings: %d"
        % (platform.name, report["current_version"], len(workloads), len(warnings)))
    for w in warnings:
        say("  warning: " + w)
    say("\nNext: open the file and review it, then send it to Retool.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

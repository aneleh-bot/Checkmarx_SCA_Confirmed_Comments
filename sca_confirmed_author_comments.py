import requests
import time
import re
import os 
import json
import base64
import pandas as pd
from datetime import datetime, timedelta, timezone
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from requests.exceptions import HTTPError, ChunkedEncodingError, ConnectionError
from urllib.parse import quote

# --------------------------------------------------
# Configuração (substitua!)
# --------------------------------------------------
AST_API_BASE   = "https://eu.ast.checkmarx.net"          # AST (Projects/Scans/Results) - Coloque url do cliente (US,US2,EU,EU2) <-------------
SCA_API_BASE   = "https://eu.api-sca.checkmarx.net"      # SCA Risk Management (comments/notes/history) - Coloque url do cliente (US,US2,EU,EU2) <-------------
CLIENT_ID = " " # Adicione ID do Cliente - OAuth <-------------
CLIENT_SECRET = " " # Adicione Secret do Cliente - OAuth <-------------
TENANT_NAME = " "                                        # Tenant do Cliente <-------------
# --------------------------------------------------

AUTH_URL       = f"https://eu.iam.checkmarx.net/auth/realms/{TENANT_NAME}/protocol/openid-connect/token"
PROJECTS_URL   = f"{AST_API_BASE}/api/projects"
SCANS_URL      = f"{AST_API_BASE}/api/scans"
RESULTS_URL    = f"{AST_API_BASE}/api/results"

# GraphQL para SCA/MOR
SCA_GQL_URL    = f"{AST_API_BASE}/api/sca/graphql/graphql"

# ------------------------------------------------
# Scans iniciados nos últimos N dias (substitua!)
# ------------------------------------------------
SCAN_LOOKBACK_DAYS = 2  # Substitua pela quantidade de dias <-------------
# ------------------------------------------------

SCAN_FROM_ISO = (datetime.now(timezone.utc) - timedelta(days=SCAN_LOOKBACK_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
PAGE_SIZE = 4000

# CSV offline (MERGE opcional – deixe vazio para desabilitar)
HISTORY_CSV = ""  # exemplo: r"C:\temp\risk_history.csv"

# =========================
# SESSION + AUTH
# =========================
session = requests.Session()
session.mount("https://", HTTPAdapter(max_retries=Retry(
    total=5, backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["GET","POST"]
)))

def get_headers():
    r = session.post(
        AUTH_URL,
        data={"grant_type":"client_credentials","client_id":CLIENT_ID,"client_secret":CLIENT_SECRET},
        timeout=(5,30)
    )
    r.raise_for_status()
    token = r.json()["access_token"]
    return {"Authorization": f"Bearer {token}", "Accept":"application/json;v=1.0"}

# =========================
# HELPERS
# =========================
CONFIRM_PAT = re.compile(r"\bconfirm(?:ed|ation|ar|ado|ação|acao)?\b", re.I)

def _is_confirmed(res: dict) -> bool:
    for k in ("state","validationState","resultState","status"):
        v = res.get(k)
        if isinstance(v, str) and v.strip().lower() == "confirmed":
            return True
    return False

def _is_sca(res: dict) -> bool:
    if (res.get("type") or "").lower() == "sca":
        return True
    return bool((res.get("data") or {}).get("packageIdentifier"))

def _result_id(r: dict) -> str:
    return str(r.get("id") or r.get("resultId") or r.get("alternateId") or r.get("similarityId") or "")

def _safe_first_line(s: str) -> str:
    return (s or "").split("\n", 1)[0].strip()

# -------------------------
# Parse do packageIdentifier -> (manager, name, version)
# Exemplos:
#  - "Npm-backslash-0.2.1" -> ("Npm", "backslash", "0.2.1")
#  - "Maven-commons-collections:commons-collections-3.2.1" -> ("Maven","commons-collections:commons-collections","3.2.1")
#  - "Maven-com.thoughtworks.xstream:xstream-1.4.5" -> ("Maven","com.thoughtworks.xstream:xstream","1.4.5")
# -------------------------
def parse_pkg(identifier: str):
    if not identifier:
        return "", "", ""
    ident = str(identifier)
    if ident.startswith(("Npm-", "npm-")):
        parts = ident.split("-", 2)
        if len(parts) == 3:
            return parts[0].replace("npm", "Npm"), parts[1], parts[2]
    if ident.startswith(("Maven-", "maven-")):
        # Maven-<group:artifact>-<version> (o nome pode ter ':')
        # pega a última "-" como separadora de versão
        try:
            last_dash = ident.rindex("-")
            manager = ident[:ident.index("-")]
            name = ident[len(manager)+1:last_dash]
            version = ident[last_dash+1:]
            manager = manager.replace("maven", "Maven")
            return manager, name, version
        except ValueError:
            pass
    # fallback genérico: Manager-name-version (3 pedaços)
    parts = ident.split("-", 2)
    if len(parts) == 3:
        return parts[0], parts[1], parts[2]
    return "", "", ""

# ========================================
# GRAPHQL: pega ações/notas e extrai autor
# ========================================
GQL_QUERY = """
query ($scanId: UUID!, $projectId: String, $isLatest: Boolean!, $packageName: String, $packageVersion: String, $packageManager: String, $vulnerabilityId: String) {
  searchPackageVulnerabilityStateAndScoreActions(
    scanId: $scanId,
    projectId: $projectId,
    isLatest: $isLatest,
    packageName: $packageName,
    packageVersion: $packageVersion,
    packageManager: $packageManager,
    vulnerabilityId: $vulnerabilityId
  ) {
    actions {
      isComment
      actionType
      actionValue
      previousActionValue
      enabled
      createdAt
      comment {
        id
        message
        createdOn
        userName
      }
    }
  }
}
""".strip()

def _author_from_graphql(headers, project_id: str, scan_id: str, res: dict) -> tuple[str, str, str]:
    # extrai variáveis
    pkg_id = (res.get("data") or {}).get("packageIdentifier") or ""
    manager, pkg_name, pkg_ver = parse_pkg(pkg_id)
    cve = (res.get("vulnerabilityDetails") or {}).get("cveName") or ""

    variables = {
        "scanId": scan_id,
        "projectId": project_id,
        "isLatest": True,
        "packageName": pkg_name or None,
        "packageVersion": pkg_ver or None,
        "packageManager": manager or None,
        "vulnerabilityId": cve or None,
    }

    # DEBUG de variáveis usadas (bom pra quando vier vazio)
    print(f"[GQL VARS] scan={scan_id} proj={project_id} mgr={manager} pkg={pkg_name} ver={pkg_ver} cve={cve}")

    payload = {"query": GQL_QUERY, "variables": variables}
    hdrs = dict(headers)
    hdrs["Accept"] = "application/json"
    hdrs["Content-Type"] = "application/json"

    try:
        r = session.post(SCA_GQL_URL, headers=hdrs, json=payload, timeout=(5, 30))
        status = r.status_code
        if status != 200:
            print(f"[GQL {status}] erro ao consultar ações.")
            return "", f"GQL_HTTP_{status}", ""
        data = r.json()
    except Exception as e:
        print(f"[GQL ERR] {e}")
        return "", "GQL_ERR", ""

    # erros GraphQL (mesmo com HTTP 200)
    if "errors" in data and data["errors"]:
        # só loga o primeiro pra não poluir
        e0 = data["errors"][0]
        print(f"[GQL ERROR] {e0.get('message')}")
        return "", "GQL_ERRORS", ""

    actions = (((data.get("data") or {}).get("searchPackageVulnerabilityStateAndScoreActions") or {}).get("actions")) or []
    if not actions:
        return "", "GQL_EMPTY", ""

    # Ordena por createdAt (asc) e decide o “melhor”
    def to_dt(s):
        try:
            return datetime.fromisoformat(str(s).replace("Z","+00:00"))
        except Exception:
            return datetime.min.replace(tzinfo=timezone.utc)

    actions.sort(key=lambda a: to_dt(a.get("createdAt")))

    # 1) prioriza ação que muda para Confirmed OU comentário que contenha “confirm”
    best = None
    for a in reversed(actions):
        action_val = str(a.get("actionValue") or "").strip().lower()
        prev_val   = str(a.get("previousActionValue") or "").strip().lower()
        msg        = ((a.get("comment") or {}).get("message") or "")
        if action_val == "confirmed" or prev_val == "to verify" and action_val:
            best = a; break
        if CONFIRM_PAT.search(msg):
            best = a; break

    # 2) senão, pega a última entrada que tenha comment.userName
    if not best:
        for a in reversed(actions):
            if (a.get("comment") or {}).get("userName"):
                best = a; break

    if not best:
        return "", "GQL_NO_MATCH", ""

    author = ((best.get("comment") or {}).get("userName") or "").strip()
    confirm_note = ""
    try:
        c = best.get("comment") or {}
        if isinstance(c, dict):
            confirm_note = str(c.get("message") or c.get("text") or c.get("note") or "").strip()
        elif isinstance(c, (str, bytes)):
            confirm_note = str(c).strip()
    except Exception:
        pass
    if not confirm_note:
        confirm_note = str(best.get("message") or best.get("text") or best.get("note") or best.get("body") or "").strip()
    return author, "GQL_actions", confirm_note

# =========================
# MERGE CSV (opcional – desabilitado se HISTORY_CSV == "")
# =========================
class HistoryIndex:
    def __init__(self): self.idx = {}
    def add(self, row: dict, pid: str):
        def g(*names):
            for n in names:
                v = row.get(n)
                if pd.notna(v) and str(v).strip(): return str(v).strip()
            return ""
        keys = [
            g("riskId","entityId","riskID"),
            g("cve","cveName","CVE"),
            g("package","packageIdentifier"),
            g("resultId"),
            g("similarityId"),
            g("alternateId","altId"),
        ]
        keys = [k for k in keys if k]
        for k in list(keys):
            for b in _b64_variants(k):
                keys.append(b)
        for k in keys:
            self.idx.setdefault((pid, k.lower()), []).append(row)

    def find(self, pid: str, candidates: list):
        for c in candidates:
            if not c: continue
            hit = self.idx.get((pid, str(c).lower()))
            if hit: return hit
        return None

def _b64_variants(s: str):
    out = set()
    if not s: return out
    raw = str(s).encode("utf-8")
    for enc in (base64.b64encode, base64.urlsafe_b64encode):
        t = enc(raw).decode("ascii")
        out.add(t); out.add(t.rstrip("="))
    return out

def load_history_index(csv_path: str) -> HistoryIndex | None:
    if not csv_path:
        return None
    if not os.path.exists(csv_path):
        print(f"[CSV MERGE] arquivo '{csv_path}' não encontrado — merge offline desabilitado.")
        return None
    try:
        df = pd.read_csv(csv_path)
    except Exception as e:
        print(f"[CSV MERGE] falha ao ler '{csv_path}': {e}")
        return None
    idx = HistoryIndex()
    for _, row in df.iterrows():
        d = {str(k).strip(): (None if pd.isna(v) else v) for k, v in row.items()}
        # tenta descobrir projectId na linha
        pid = ""
        for cand in ("projectId","ProjectId","project_id","projectID"):
            if cand in d and d[cand]:
                pid = str(d[cand]).strip(); break
        idx.add(d, pid or "")
    print(f"[CSV MERGE] carregado '{csv_path}' com {len(df)} linhas.")
    return idx

# =========================
# PAGINAÇÃO (AST)
# =========================
def list_projects(headers):
    acc, off = [], 0
    while True:
        r = session.get(PROJECTS_URL, headers=headers, params={"limit":PAGE_SIZE,"offset":off}, timeout=(5,30))
        r.raise_for_status()
        batch = r.json().get("projects", [])
        if not batch: break
        acc += batch; off += PAGE_SIZE
    return acc

def list_scans_for_project(headers, project_id):
    acc, off = [], 0
    while True:
        try:
            r = session.get(SCANS_URL, headers=headers, timeout=(5,30),
                            params={'project-id':project_id,'from-date':SCAN_FROM_ISO,'limit':PAGE_SIZE,'offset':off})
            r.raise_for_status()
        except HTTPError as e:
            if e.response is not None and e.response.status_code == 401:
                print(f"[WARN] não autorizado para project {project_id}, pulando."); return []
            raise
        batch = r.json().get("scans", [])
        if not batch: break
        acc += batch; off += PAGE_SIZE
    return acc

def get_results_for_scan(headers, scan_id):
    acc, off = [], 0
    while True:
        try:
            r = session.get(RESULTS_URL, headers=headers, timeout=(5,30),
                            params={'scan-id':scan_id,'limit':PAGE_SIZE,'offset':off,
                                    'includeNotes':'true','includeComments':'true',
                                    'includeHistory':'true','includeValidation':'true'})
            r.raise_for_status()
            batch = r.json().get("results", [])
        except (ChunkedEncodingError, ConnectionError):
            print(f"[WARN] conexão resetada no offset {off}, re-tentando..."); time.sleep(2); continue
        if not batch: break
        acc += batch; off += PAGE_SIZE
    return acc

# =========================
# MAIN
# =========================
def collect_confirmed_sca() -> pd.DataFrame:
    headers = get_headers()
    projects = list_projects(headers)
    print(f"Projetos encontrados: {len(projects)}")

    hist_idx = load_history_index(HISTORY_CSV)

    rows = []
    for proj in projects:
        headers = get_headers()  # token fresco
        pid = proj.get("id"); pname = proj.get("name","<unknown>")
        scans = list_scans_for_project(headers, pid)
        print(f"Projeto '{pname}': {len(scans)} scans desde {SCAN_FROM_ISO}")

        for scan in scans:
            sid = scan.get("id")
            results = get_results_for_scan(headers, sid)
            confirmed = [r for r in results if _is_confirmed(r) and _is_sca(r)]
            if not confirmed:
                continue
            print(f"  Scan {sid}: {len(confirmed)} vulnerabilidades SCA CONFIRMADAS")

            for res in confirmed:
                rid = _result_id(res)
                vuln = (res.get('vulnerabilityDetails',{}).get('cveName') or
                        (res.get('data',{}).get('packageIdentifier') or _safe_first_line(res.get('description',''))))

                # 1) Tenta GraphQL (SCA/MOR)
                author, source, confirm_note = _author_from_graphql(headers, pid, sid, res)

                # 2) Fallback: CSV (se ligado)
                if not author and hist_idx is not None:
                    candidates = []
                    candidates += [res.get("alternateId") or ""]
                    candidates += [rid, str(res.get("similarityId") or "")]
                    candidates += [(res.get("data") or {}).get("packageIdentifier") or ""]
                    candidates += [(res.get("vulnerabilityDetails") or {}).get("cveName") or ""]
                    candidates = [c for c in candidates if c]
                    hit = hist_idx.find(pid or "", candidates)
                    if hit:
                        # pega a última linha
                        last = list(hit)[-1]
                        author = str(last.get("author") or last.get("createdBy") or last.get("userName") or "").strip()
                        if author:
                            source = "CSV_MERGE"

                if not author:
                    print(f"[AUTHOR EMPTY] pid={pid} rid={rid} cve/pkg={vuln} source={source}")

                rows.append({
                    "Project Name":   pname,
                    "Project Id":     pid,
                    "Scan Id":        sid,
                    "Result Id":      rid,
                    "CVE/Package":    vuln,
                    "Severity":       res.get("severity",""),
                    "State":          res.get("state") or res.get("validationState") or res.get("resultState") or res.get("status",""),
                    "Author":         author,
                    "Author Source":  source,
                    "Detected First": res.get("firstFoundAt",""),
                    "Detected Last":  res.get("foundAt","") or res.get("lastFoundAt","") or res.get("updatedAt",""),
                    "Confirm Note":   confirm_note or ""
                })
    return pd.DataFrame(rows)

def export_report(df, excel_file='checkmarx_sca_confirmed.xlsx'):
    if df.empty:
        print("Nenhuma SCA confirmada encontrada."); return
    try:
        with pd.ExcelWriter(excel_file, engine='openpyxl') as w:
            df.to_excel(w, sheet_name='SCA Confirmadas', index=False)
        print(f"Relatório gerado: {excel_file}")
    except PermissionError:
        # arquivo provavelmente aberto no Excel/OneDrive — salva com timestamp
        base, ext = os.path.splitext(excel_file)
        alt = f"{base}_{datetime.now().strftime('%Y%m%d_%H%M%S')}{ext}"
        with pd.ExcelWriter(alt, engine='openpyxl') as w:
            df.to_excel(w, sheet_name='SCA Confirmadas', index=False)
        print(f"[WARN] '{excel_file}' está em uso. Salvei como: {alt}")
    # (opcional) exporta CSV lado a lado
    try:
        csv_name = os.path.splitext(excel_file)[0] + ".csv"
        df.to_csv(csv_name, index=False)
        print(f"CSV gerado: {csv_name}")
    except Exception as e:
        print(f"[WARN] falha ao gerar CSV auxiliar: {e}")

if __name__ == "__main__":
    df = collect_confirmed_sca()
    export_report(df)
    if not df.empty:
        print("\n=== SCA Confirmadas ===")
        print(df[["Project Name","CVE/Package","Severity","Author","Author Source"]])

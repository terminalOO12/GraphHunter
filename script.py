#!/usr/bin/env python3
"""
GraphHunter - Final UI v8
Show both name and email/UPN for members, owners and role members.

Usage:
    python3 graphhunter_final_v8.py --token <GRAPH_TOKEN> --serve
"""
from typing import Dict, Any, List, Optional
import argparse, requests, time, threading, json, webbrowser, sys, os
from flask import Flask, jsonify, request, send_from_directory

API_BASE = "https://graph.microsoft.com/v1.0"
CACHE_TTL = 60.0  # seconds

# -------------------------
# HTTP helpers (backoff + paginator)
# -------------------------
def request_with_backoff(url: str, headers: Dict[str, str], params: Dict[str, Any] = None, method: str = "GET"):
    max_retries = 4
    backoff = 1.0
    for attempt in range(1, max_retries + 1):
        try:
            resp = requests.request(method, url, headers=headers, params=params, timeout=30)
        except requests.RequestException:
            if attempt == max_retries:
                raise
            time.sleep(backoff)
            backoff *= 2
            continue

        if resp.status_code in (429, 503) or 500 <= resp.status_code < 600:
            retry_after = resp.headers.get("Retry-After")
            try:
                wait = float(retry_after) if retry_after and retry_after.isdigit() else backoff
            except Exception:
                wait = backoff
            if attempt == max_retries:
                resp.raise_for_status()
            time.sleep(wait)
            backoff *= 2
            continue

        return resp
    raise RuntimeError("Exceeded retries")

def get_all(endpoint: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    url = f"{API_BASE}/{endpoint}"
    while url:
        resp = request_with_backoff(url, headers)
        if resp.status_code == 204:
            break
        try:
            data = resp.json()
        except ValueError:
            resp.raise_for_status()
        if "value" in data and isinstance(data["value"], list):
            results.extend(data["value"])
            url = data.get("@odata.nextLink")
        else:
            if isinstance(data, dict):
                results.append(data)
            break
    return results

# -------------------------
# Summary fetchers
# -------------------------
def fetch_users(headers):
    return get_all("users?$select=id,displayName,userPrincipalName,accountEnabled,userType,department", headers)

def fetch_groups(headers):
    return get_all("groups?$select=id,displayName,mail,groupTypes,membershipRule,securityEnabled,mailEnabled", headers)

def fetch_directory_roles(headers):
    roles = get_all("directoryRoles", headers)
    out = []
    for r in roles:
        role_id = r.get("id")
        obj = {
            "id": role_id,
            "displayName": r.get("displayName"),
            "description": r.get("description"),
            "roleTemplateId": r.get("roleTemplateId"),
            "members_count": None
        }
        try:
            members = get_all(f"directoryRoles/{role_id}/members?$select=id,displayName,userPrincipalName,mail", headers)
            obj["members_count"] = len(members)
        except Exception:
            obj["members_count"] = None
        out.append(obj)
    return out

def fetch_app_registrations(headers):
    apps = get_all("applications?$select=id,displayName,createdDateTime,publisherDomain,signInAudience", headers)
    out = []
    for a in apps:
        app_id = a.get("id")
        obj = {
            "id": app_id,
            "displayName": a.get("displayName"),
            "createdDateTime": a.get("createdDateTime"),
            "publisherDomain": a.get("publisherDomain"),
            "signInAudience": a.get("signInAudience"),
            "owners_count": None
        }
        try:
            owners = get_all(f"applications/{app_id}/owners?$select=id,displayName,userPrincipalName,mail", headers)
            obj["owners_count"] = len(owners)
        except Exception:
            obj["owners_count"] = None
        out.append(obj)
    return out

def fetch_service_principals(headers):
    sps = get_all("servicePrincipals?$select=id,displayName,appId,publisherName", headers)
    out = []
    for sp in sps:
        out.append({
            "id": sp.get("id"),
            "displayName": sp.get("displayName"),
            "appId": sp.get("appId"),
            "publisherName": sp.get("publisherName")
        })
    return out

def fetch_devices(headers):
    return get_all("devices?$select=id,displayName,deviceId,operatingSystem,operatingSystemVersion,trustType,approximateLastSignInDateTime,deviceTrustType", headers)

def fetch_administrative_units(headers):
    return get_all("administrativeUnits?$select=id,displayName,description", headers)

SECTION_FETCHERS = {
    "users": fetch_users,
    "groups": fetch_groups,
    "directoryRoles": fetch_directory_roles,
    "applications": fetch_app_registrations,
    "servicePrincipals": fetch_service_principals,
    "devices": fetch_devices,
    "administrativeUnits": fetch_administrative_units
}

# -------------------------
# Cache
# -------------------------
_cache = {}
_cache_lock = threading.Lock()

def _normalize_fetched_data(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if "value" in data and isinstance(data["value"], list):
            return data["value"]
        return [data]
    return []

def get_section_cached(section: str, headers: Dict[str,str], force_refresh: bool=False):
    now = time.time()
    with _cache_lock:
        ent = _cache.get(section)
        if ent and not force_refresh and (now - ent["ts"] < CACHE_TTL):
            return {"cached": True, "fetched_at": ent["ts"], "data": ent["data"]}
    fetcher = SECTION_FETCHERS.get(section)
    if not fetcher:
        raise ValueError("unknown section")
    data = fetcher(headers)
    data = _normalize_fetched_data(data)
    with _cache_lock:
        _cache[section] = {"ts": now, "data": data}
    return {"cached": False, "fetched_at": now, "data": data}

def prefetch_all_sections(headers: Dict[str,str]):
    for s in SECTION_FETCHERS.keys():
        try:
            res = get_section_cached(s, headers, force_refresh=True)
            print(f"[prefetch] section '{s}' fetched ({len(res['data'])} items).")
        except Exception as e:
            print(f"[prefetch] section '{s}' failed: {e}")
            with _cache_lock:
                _cache[s] = {"ts": time.time(), "data": []}

# -------------------------
# Deterministic object resolvers (targeted GETs)
# -------------------------
def _resolve_group(id: str, headers: Dict[str,str]) -> Optional[Dict[str,Any]]:
    try:
        r = request_with_backoff(f"{API_BASE}/groups/{id}?$select=id,displayName,mail,groupTypes", headers)
        if r.status_code == 200:
            return r.json()
    except Exception:
        return None
    return None

def _resolve_directory_role(id: str, headers: Dict[str,str]) -> Optional[Dict[str,Any]]:
    try:
        r = request_with_backoff(f"{API_BASE}/directoryRoles/{id}?$select=id,displayName", headers)
        if r.status_code == 200:
            return r.json()
    except Exception:
        return None
    return None

def _resolve_user(id: str, headers: Dict[str,str]) -> Optional[Dict[str,Any]]:
    try:
        r = request_with_backoff(f"{API_BASE}/users/{id}?$select=id,displayName,userPrincipalName,mail", headers)
        if r.status_code == 200:
            return r.json()
    except Exception:
        return None
    return None

def _resolve_service_principal(id: str, headers: Dict[str,str]) -> Optional[Dict[str,Any]]:
    try:
        r = request_with_backoff(f"{API_BASE}/servicePrincipals/{id}?$select=id,displayName,appId", headers)
        if r.status_code == 200:
            return r.json()
    except Exception:
        return None
    return None

def _resolve_application(id: str, headers: Dict[str,str]) -> Optional[Dict[str,Any]]:
    try:
        r = request_with_backoff(f"{API_BASE}/applications/{id}?$select=id,displayName,appId", headers)
        if r.status_code == 200:
            return r.json()
    except Exception:
        return None
    return None

# -------------------------
# Details (robust; request userPrincipalName and mail where useful)
# -------------------------
def fetch_user_detail(user_id: str, headers: Dict[str,str]):
    fields = "id,displayName,userPrincipalName,accountEnabled,userType,department,jobTitle,mobilePhone,officeLocation,createdDateTime,onPremisesSyncEnabled,onPremisesSamAccountName,mail,onPremisesLastPasswordSyncDateTime"
    resp = request_with_backoff(f"{API_BASE}/users/{user_id}?$select={fields}", headers)
    user = resp.json()

    member_of_raw = None
    member_of_error = None
    try:
        # avoid @odata.type in $select; include displayName and id
        member_of_raw = get_all(f"users/{user_id}/memberOf?$select=id,displayName", headers)
    except Exception as e:
        member_of_raw = None
        member_of_error = str(e)

    resolved_groups = []
    resolved_roles = []
    unresolved = []

    if isinstance(member_of_raw, list):
        for mo in member_of_raw:
            mo_id = mo.get("id")
            if not mo_id:
                unresolved.append({"raw": mo})
                continue
            g = _resolve_group(mo_id, headers)
            if g:
                resolved_groups.append({
                    "id": g.get("id"),
                    "displayName": g.get("displayName") or g.get("id"),
                    "mail": g.get("mail"),
                    "groupTypes": g.get("groupTypes", [])
                })
                continue
            r = _resolve_directory_role(mo_id, headers)
            if r:
                resolved_roles.append({
                    "id": r.get("id"),
                    "displayName": r.get("displayName") or r.get("id")
                })
                continue
            u = _resolve_user(mo_id, headers)
            if u:
                resolved_groups.append({
                    "id": u.get("id"),
                    "displayName": u.get("displayName") or u.get("userPrincipalName") or u.get("id"),
                    "upn": u.get("userPrincipalName"),
                    "mail": u.get("mail")
                })
                continue
            sp = _resolve_service_principal(mo_id, headers)
            if sp:
                resolved_groups.append({
                    "id": sp.get("id"),
                    "displayName": sp.get("displayName") or sp.get("appId") or sp.get("id"),
                    "appId": sp.get("appId"),
                    "type": "servicePrincipal"
                })
                continue
            app = _resolve_application(mo_id, headers)
            if app:
                resolved_groups.append({
                    "id": app.get("id"),
                    "displayName": app.get("displayName") or app.get("appId") or app.get("id"),
                    "appId": app.get("appId"),
                    "type": "application"
                })
                continue

            unresolved.append({"id": mo_id, "raw": mo})

    if not resolved_groups and not resolved_roles and not member_of_error:
        try:
            fb = get_all(f"groups?$filter=members/any(m: m/id eq '{user_id}')&$select=id,displayName,groupTypes,mail", headers)
            for g in fb:
                resolved_groups.append({
                    "id": g.get("id"),
                    "displayName": g.get("displayName") or g.get("id"),
                    "mail": g.get("mail"),
                    "groupTypes": g.get("groupTypes", [])
                })
        except Exception as e:
            member_of_error = member_of_error or str(e)

    # Owned applications
    owned_apps_raw = None
    owned_error = None
    owned_apps = []
    try:
        owned_apps_raw = get_all(f"users/{user_id}/ownedObjects?$select=id,displayName,appId", headers)
    except Exception as e:
        owned_apps_raw = None
        owned_error = str(e)

    if isinstance(owned_apps_raw, list) and owned_apps_raw:
        for o in owned_apps_raw:
            oid = o.get("id")
            app = _resolve_application(oid, headers)
            if app:
                owned_apps.append({
                    "id": app.get("id"),
                    "displayName": app.get("displayName") or app.get("appId") or app.get("id"),
                    "appId": app.get("appId")
                })
                continue
            sp = _resolve_service_principal(oid, headers)
            if sp:
                owned_apps.append({
                    "id": sp.get("id"),
                    "displayName": sp.get("displayName") or sp.get("appId") or sp.get("id"),
                    "appId": sp.get("appId"),
                    "type": "servicePrincipal"
                })
                continue
            owned_apps.append({
                "id": oid,
                "displayName": o.get("displayName") or o.get("appId") or oid,
                "appId": o.get("appId")
            })

    if not owned_apps and not owned_error:
        try:
            fb_apps = get_all(f"applications?$filter=owners/any(o: o/id eq '{user_id}')&$select=id,displayName,appId", headers)
            for a in fb_apps:
                owned_apps.append({
                    "id": a.get("id"),
                    "displayName": a.get("displayName") or a.get("appId") or a.get("id"),
                    "appId": a.get("appId")
                })
        except Exception as e:
            owned_error = owned_error or str(e)

    # password / sign-in
    last_password_change = None
    try:
        pw_methods = get_all(f"users/{user_id}/authentication/passwordMethods", headers)
        if isinstance(pw_methods, list) and pw_methods:
            m = pw_methods[0]
            last_password_change = m.get("lastPasswordChangeDateTime") or m.get("createdDateTime")
    except Exception:
        last_password_change = None
    if not last_password_change:
        last_password_change = user.get("onPremisesLastPasswordSyncDateTime")

    last_signin = None
    try:
        resp2 = request_with_backoff(f"{API_BASE}/users/{user_id}?$select=signInActivity", headers)
        j2 = resp2.json()
        if isinstance(j2, dict) and j2.get("signInActivity"):
            last_signin = j2["signInActivity"].get("lastSignInDateTime")
    except Exception:
        last_signin = None
    if not last_signin:
        try:
            signins = get_all(f"auditLogs/signIns?$filter=userId eq '{user_id}'&$orderby=createdDateTime desc&$top=1", headers)
            if isinstance(signins, list) and signins:
                last_signin = signins[0].get("createdDateTime")
        except Exception:
            last_signin = None

    return {
        "user": user,
        "groups": resolved_groups,
        "directoryRoles": resolved_roles,
        "ownedApplications": owned_apps,
        "memberOfError": member_of_error,
        "ownedObjectsError": owned_error,
        "unresolvedMemberOf": unresolved,
        "lastPasswordChange": last_password_change,
        "lastSignIn": last_signin
    }

# -------------------------
# Other detail fetchers (request email/UPN when possible)
# -------------------------
def fetch_group_detail(group_id: str, headers: Dict[str,str]):
    resp = request_with_backoff(f"{API_BASE}/groups/{group_id}?$select=id,displayName,mail,groupTypes,membershipRule,securityEnabled,mailEnabled,createdDateTime", headers)
    group_obj = resp.json()
    members = []
    try:
        members = get_all(f"groups/{group_id}/members?$select=id,displayName,userPrincipalName,mail", headers)
    except Exception as e:
        members = {"error": str(e)}
    return {"group": group_obj, "members": members}

def fetch_role_detail(role_id: str, headers: Dict[str,str]):
    resp = request_with_backoff(f"{API_BASE}/directoryRoles/{role_id}", headers)
    role = resp.json()
    members = []
    try:
        members = get_all(f"directoryRoles/{role_id}/members?$select=id,displayName,userPrincipalName,mail", headers)
    except Exception as e:
        members = {"error": str(e)}
    return {"role": role, "members": members}

def fetch_application_detail(app_id: str, headers: Dict[str,str]):
    resp = request_with_backoff(f"{API_BASE}/applications/{app_id}", headers)
    app = resp.json()
    owners = []
    try:
        owners_raw = get_all(f"applications/{app_id}/owners?$select=id,displayName,userPrincipalName,mail", headers)
        for o in owners_raw:
            owners.append({
                "id": o.get("id"),
                "displayName": o.get("displayName") or o.get("userPrincipalName") or o.get("mail") or o.get("id"),
                "userPrincipalName": o.get("userPrincipalName"),
                "mail": o.get("mail"),
                "objectType": (o.get("@odata.type") or "").split('.')[-1].lower() if o.get("@odata.type") else "unknown"
            })
    except Exception as e:
        owners = {"error": str(e)}
    return {"application": app, "owners": owners}

def fetch_service_principal_detail(sp_id: str, headers: Dict[str,str]):
    resp = request_with_backoff(f"{API_BASE}/servicePrincipals/{sp_id}", headers)
    sp = resp.json()
    return {"servicePrincipal": sp}

def fetch_device_detail(device_id: str, headers: Dict[str,str]):
    resp = request_with_backoff(f"{API_BASE}/devices/{device_id}", headers)
    d = resp.json()
    owners = []
    try:
        owners = get_all(f"devices/{device_id}/registeredOwners?$select=id,displayName,userPrincipalName,mail", headers)
    except Exception:
        owners = []
    return {"device": d, "owners": owners}

def fetch_administrative_unit_detail(au_id: str, headers: Dict[str,str]):
    resp = request_with_backoff(f"{API_BASE}/administrativeUnits/{au_id}", headers)
    au = resp.json()
    members = []
    try:
        members = get_all(f"administrativeUnits/{au_id}/members?$select=id,displayName,userPrincipalName,mail", headers)
    except Exception:
        members = []
    return {"administrativeUnit": au, "members": members}

# -------------------------
# Flask app factory & API endpoints
# -------------------------
def create_app(bearer_token: str, host="127.0.0.1", port=5000):
    app = Flask(__name__, static_folder=None)
    headers = {"Authorization": f"Bearer {bearer_token}", "Accept": "application/json"}

    @app.route("/asset/<path:filename>")
    def asset(filename):
        return send_from_directory("asset", filename)

    @app.route("/api/sections")
    def api_sections():
        with _cache_lock:
            sections = []
            for s in SECTION_FETCHERS.keys():
                ent = _cache.get(s)
                sections.append({
                    "name": s,
                    "cached": bool(ent),
                    "fetched_at": ent["ts"] if ent else None,
                    "count": len(ent["data"]) if ent else 0
                })
        return jsonify({"sections": sections})

    @app.route("/api/section/<section>")
    def api_section(section):
        if section not in SECTION_FETCHERS:
            return jsonify({"error": "unknown section"}), 404
        force = request.args.get("refresh", "false").lower() in ("1", "true", "yes")
        summary_only = request.args.get("summary", "true").lower() in ("1", "true", "yes")
        try:
            res = get_section_cached(section, headers, force_refresh=force)
            data = res["data"]
            if summary_only:
                if section == "users":
                    summary = [{"id": u.get("id"), "displayName": u.get("displayName") or u.get("userPrincipalName"), "userPrincipalName": u.get("userPrincipalName"), "accountEnabled": u.get("accountEnabled"), "userType": u.get("userType")} for u in data]
                elif section == "groups":
                    summary = [{"id": g.get("id"), "displayName": g.get("displayName"), "mail": g.get("mail"), "groupTypes": g.get("groupTypes", [])} for g in data]
                elif section == "directoryRoles":
                    summary = [{"id": r.get("id"), "displayName": r.get("displayName"), "members_count": r.get("members_count")} for r in data]
                elif section == "applications":
                    summary = [{"id": a.get("id"), "displayName": a.get("displayName"), "owners_count": a.get("owners_count"), "createdDateTime": a.get("createdDateTime")} for a in data]
                elif section == "servicePrincipals":
                    summary = [{"id": s.get("id"), "displayName": s.get("displayName"), "appId": s.get("appId")} for s in data]
                elif section == "devices":
                    rows = []
                    for d in data:
                        os_name = d.get("operatingSystem") or ""
                        ver = d.get("operatingSystemVersion") or ""
                        os_full = (os_name + (" " + ver if ver else "")).strip()
                        if not os_full:
                            os_full = d.get("deviceTrustType") or d.get("trustType") or ""
                        rows.append({"id": d.get("id"), "displayName": d.get("displayName"), "deviceId": d.get("deviceId"), "os": os_full})
                    summary = rows
                elif section == "administrativeUnits":
                    summary = [{"id": au.get("id"), "displayName": au.get("displayName"), "description": au.get("description")} for au in data]
                else:
                    summary = data
                return jsonify({"section": section, "cached": res["cached"], "fetched_at": res["fetched_at"], "summary": summary})
            else:
                return jsonify({"section": section, "cached": res["cached"], "fetched_at": res["fetched_at"], "data": data})
        except requests.HTTPError as he:
            return jsonify({"error": "http", "detail": str(he)}), 502
        except Exception as e:
            return jsonify({"error": "fetch", "detail": str(e)}), 500

    @app.route("/api/section/<section>/item/<item_id>")
    def api_section_item(section, item_id):
        if section not in SECTION_FETCHERS:
            return jsonify({"error": "unknown section"}), 404
        item_id = request.view_args["item_id"]
        try:
            if section == "users":
                details = fetch_user_detail(item_id, headers)
                return jsonify({"section": section, "item_id": item_id, "details": details})
            elif section == "groups":
                details = fetch_group_detail(item_id, headers)
                return jsonify({"section": section, "item_id": item_id, "details": details})
            elif section == "directoryRoles":
                details = fetch_role_detail(item_id, headers)
                return jsonify({"section": section, "item_id": item_id, "details": details})
            elif section == "applications":
                details = fetch_application_detail(item_id, headers)
                return jsonify({"section": section, "item_id": item_id, "details": details})
            elif section == "servicePrincipals":
                details = fetch_service_principal_detail(item_id, headers)
                return jsonify({"section": section, "item_id": item_id, "details": details})
            elif section == "devices":
                details = fetch_device_detail(item_id, headers)
                return jsonify({"section": section, "item_id": item_id, "details": details})
            elif section == "administrativeUnits":
                details = fetch_administrative_unit_detail(item_id, headers)
                return jsonify({"section": section, "item_id": item_id, "details": details})
            else:
                return jsonify({"error": "unsupported section detail"}), 400
        except requests.HTTPError as he:
            return jsonify({"error": "http", "detail": str(he)}), 502
        except Exception as e:
            return jsonify({"error": "fetch", "detail": str(e)}), 500

    @app.route("/")
    def index():
        return INDEX_HTML

    return app

# -------------------------
# Single-page client (HTML/JS)
# -------------------------
INDEX_HTML = r"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>GraphHunter</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>
    body{font-family:Inter,Helvetica,Arial,sans-serif;background:#eaf4fb;margin:0;padding:18px;min-height:100vh;}
    .wrap{max-width:1100px;margin:0 auto}
    header{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
    h1{margin:0;font-size:38px;line-height:1.1}
    .subtitle{font-size:16px;color:#374151;margin-top:2px;}
    .nav{display:flex;gap:8px;flex-wrap:wrap}
    .btn{padding:8px 12px;border-radius:8px;border:1px solid #e6e8ee;background:#fff;cursor:pointer}
    .btn.active{background:#111827;color:#fff;border-color:#111827}
    .content{margin-top:12px}
    .section{background:#fff;padding:14px;border-radius:10px;box-shadow:0 8px 20px rgba(16,24,40,0.06);margin-bottom:12px}
    table{width:100%;border-collapse:collapse}
    th,td{padding:8px;border-bottom:1px solid #f3f4f6;text-align:left;vertical-align:top}
    pre{white-space:pre-wrap;word-wrap:break-word;margin:0;font-family:inherit}
    .muted{color:#6b7280;font-size:13px}
    .owners{margin-top:8px}
    .detail{background:#fff;padding:12px;border-radius:8px;margin-top:8px}
    .mini{font-size:13px;color:#374151}
    thead th { font-weight:600; text-transform:none; }
    .member-email { color:#6b7280; font-size:13px; margin-left:6px; }
  </style>
</head>
<body>
<div class="wrap">
  <header>
    <div>
      <h1>GraphHunter</h1>
      <div class="subtitle">Developed By - Saksham Agrawal</div>
    </div>
    <div id="status" class="muted" style="display:none"></div>
  </header>

  <div class="nav" id="nav"></div>
  <div class="content" id="content"><div class="section"><em>Choose a section above to load data.</em></div></div>
</div>

<script>
const SECTIONS = ["users","groups","directoryRoles","applications","servicePrincipals","devices","administrativeUnits"];
const DISPLAY = {
  users: "Users",
  groups: "Groups",
  directoryRoles: "Directory roles",
  applications: "Applications",
  servicePrincipals: "Service principals",
  devices: "Devices",
  administrativeUnits: "Administrative units"
};

const nav = document.getElementById('nav'), content = document.getElementById('content'), status = document.getElementById('status');
let current = null;
function escapeHtml(t){ return String(t).replace(/[&<>"']/g, m=> ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[m]); }
function setStatus(t){ if(status) status.textContent = "Status: "+t; }

function buildNav(){
  SECTIONS.forEach(s=>{
    const b = document.createElement('button');
    b.className = 'btn';
    b.dataset.section = s;
    b.textContent = DISPLAY[s] || s;
    b.addEventListener('click', ()=> selectSection(s, b));
    nav.appendChild(b);
  });
}

async function selectSection(section, button){
  Array.from(nav.querySelectorAll('button')).forEach(b=>b.classList.remove('active'));
  button.classList.add('active');
  current = section;
  await loadSection(section, true);
}

async function fetchJSON(url){
  setStatus('fetching');
  const r = await fetch(url);
  setStatus('idle');
  if(!r.ok){
    let body = {};
    try { body = await r.json(); } catch(e) {}
    throw new Error(body && body.error ? (JSON.stringify(body.error) + ' ' + (body.error && body.error.message? body.error.message : '')) : 'HTTP '+r.status);
  }
  return r.json();
}

/* Summary renderers */
function renderUsersSummary(list){
  if(!list || list.length===0) return '<div class="section"><h3>Users (0)</h3><div class="muted">No users found</div></div>';
  let out = '<div class="section"><h3>Users ('+list.length+')</h3><table><thead><tr><th>User</th><th>UPN</th><th>Enabled</th><th>Action</th></tr></thead><tbody>';
  list.forEach(u=>{
    out += '<tr>';
    out += '<td><strong>'+escapeHtml(u.displayName||'')+'</strong></td>';
    out += '<td class="mini"><pre>'+escapeHtml(u.userPrincipalName||'')+'</pre></td>';
    out += '<td class="mini">'+escapeHtml(String(u.accountEnabled))+'</td>';
    out += '<td><button class="btn" data-action="user" data-id="'+escapeHtml(u.id||'')+'">Details</button></td>';
    out += '</tr>';
  });
  out += '</tbody></table></div><div id="detail"></div>';
  return out;
}
function renderGroupsSummary(list){
  if(!list || list.length===0) return '<div class="section"><h3>Groups (0)</h3><div class="muted">No groups found</div></div>';
  let out = '<div class="section"><h3>Groups ('+list.length+')</h3><table><thead><tr><th>Group</th><th>Type</th><th>Action</th></tr></thead><tbody>';
  list.forEach(g=>{
    const type = (g.groupTypes && g.groupTypes.length)? g.groupTypes.join(', ') : (g.securityEnabled? 'Security' : 'Microsoft 365 / Office');
    out += '<tr>';
    out += '<td><strong>'+escapeHtml(g.displayName||'')+'</strong><div class="muted">'+escapeHtml(g.mail || '')+'</div></td>';
    out += '<td class="mini">'+escapeHtml(String(type))+'</td>';
    out += '<td><button class="btn" data-action="group" data-id="'+escapeHtml(g.id||'')+'">Members</button></td>';
    out += '</tr>';
  });
  out += '</tbody></table></div><div id="detail"></div>';
  return out;
}
function renderRolesSummary(list){
  if(!list || list.length===0) return '<div class="section"><h3>Directory roles (0)</h3><div class="muted">No active directory roles</div></div>';
  let out = '<div class="section"><h3>Directory roles ('+list.length+')</h3><table><thead><tr><th>Role</th><th>Assigned</th><th>Action</th></tr></thead><tbody>';
  list.forEach(r=>{
    out += '<tr>';
    out += '<td><strong>'+escapeHtml(r.displayName||'')+'</strong></td>';
    out += '<td class="mini">'+(r.members_count===null? 'N/A' : escapeHtml(String(r.members_count)))+'</td>';
    out += '<td><button class="btn" data-action="role" data-id="'+escapeHtml(r.id||'')+'">View members</button></td>';
    out += '</tr>';
  });
  out += '</tbody></table></div><div id="detail"></div>';
  return out;
}
function renderAppsSummary(list){
  if(!list || list.length===0) return '<div class="section"><h3>Applications (0)</h3><div class="muted">No apps</div></div>';
  let out = '<div class="section"><h3>Applications ('+list.length+')</h3><table><thead><tr><th>Name</th><th>Owners</th><th>Created</th><th>Action</th></tr></thead><tbody>';
  list.forEach(a=>{
    out += '<tr>';
    out += '<td><strong>'+escapeHtml(a.displayName||'')+'</strong></td>';
    out += '<td class="mini">'+(a.owners_count===null? 'N/A' : escapeHtml(String(a.owners_count)))+'</td>';
    out += '<td class="mini">'+escapeHtml(a.createdDateTime||'')+'</td>';
    out += '<td><button class="btn" data-action="app" data-id="'+escapeHtml(a.id||'')+'">Details</button></td>';
    out += '</tr>';
  });
  out += '</tbody></table></div><div id="detail"></div>';
  return out;
}
function renderSPsSummary(list){
  if(!list || list.length===0) return '<div class="section"><h3>Service principals (0)</h3><div class="muted">No items</div></div>';
  let out = '<div class="section"><h3>Service principals ('+list.length+')</h3><table><thead><tr><th>Name</th><th>AppId</th><th>Action</th></tr></thead><tbody>';
  list.forEach(s=>{
    out += '<tr>';
    out += '<td><strong>'+escapeHtml(s.displayName||'')+'</strong></td>';
    out += '<td class="mini"><pre>'+escapeHtml(s.appId||'')+'</pre></td>';
    out += '<td><button class="btn" data-action="sp" data-id="'+escapeHtml(s.id||'')+'">Details</button></td>';
    out += '</tr>';
  });
  out += '</tbody></table></div><div id="detail"></div>';
  return out;
}
function renderDevicesSummary(list){
  if(!list || list.length===0) return '<div class="section"><h3>Devices (0)</h3><div class="muted">No devices</div></div>';
  let out = '<div class="section"><h3>Devices ('+list.length+')</h3><table><thead><tr><th>Name</th><th>DeviceId</th><th>OS</th><th>Action</th></tr></thead><tbody>';
  list.forEach(d=>{
    out += '<tr>';
    out += '<td><strong>'+escapeHtml(d.displayName||'')+'</strong></td>';
    out += '<td class="mini"><pre>'+escapeHtml(d.deviceId||'')+'</pre></td>';
    out += '<td class="mini">'+escapeHtml(d.os||'')+'</td>';
    out += '<td><button class="btn" data-action="device" data-id="'+escapeHtml(d.id||'')+'">Details</button></td>';
    out += '</tr>';
  });
  out += '</tbody></table></div><div id="detail"></div>';
  return out;
}
function renderAUsSummary(list){
  if(!list || list.length===0) return '<div class="section"><h3>Administrative units (0)</h3><div class="muted">No administrative units</div></div>';
  let out = '<div class="section"><h3>Administrative units ('+list.length+')</h3><table><thead><tr><th>Name</th><th>Description</th><th>Action</th></tr></thead><tbody>';
  list.forEach(a=>{
    out += '<tr>';
    out += '<td><strong>'+escapeHtml(a.displayName||'')+'</strong></td>';
    out += '<td class="mini">'+escapeHtml(a.description||'')+'</td>';
    out += '<td><button class="btn" data-action="au" data-id="'+escapeHtml(a.id||'')+'">Details</button></td>';
    out += '</tr>';
  });
  out += '</tbody></table></div><div id="detail"></div>';
  return out;
}

async function loadSection(section, summary=true){
  content.innerHTML = '<div class="section">Loading '+escapeHtml(section)+' ...</div>';
  try {
    const j = await fetchJSON('/api/section/'+encodeURIComponent(section) + (summary? '' : '?summary=false'));
    const summaryList = j.summary || j.data || [];
    let html = '';
    if(section === 'users') html = renderUsersSummary(summaryList);
    else if(section === 'groups') html = renderGroupsSummary(summaryList);
    else if(section === 'directoryRoles') html = renderRolesSummary(summaryList);
    else if(section === 'applications') html = renderAppsSummary(summaryList);
    else if(section === 'servicePrincipals') html = renderSPsSummary(summaryList);
    else if(section === 'devices') html = renderDevicesSummary(summaryList);
    else if(section === 'administrativeUnits') html = renderAUsSummary(summaryList);
    else html = '<div class="section"><pre>'+escapeHtml(JSON.stringify(summaryList, null, 2))+'</pre></div>';
    html = '<div class="section"><button class="btn" id="refreshBtn">Refresh</button> <button class="btn" id="rawBtn">Show raw JSON</button></div>' + html;
    content.innerHTML = html;
    document.getElementById('refreshBtn')?.addEventListener('click', ()=> refreshSection());
    document.getElementById('rawBtn')?.addEventListener('click', ()=> showRaw());
    window.scrollTo(0,0);
  } catch (err) {
    content.innerHTML = '<div class="section"><strong>Error:</strong> '+escapeHtml(String(err.message))+'</div>';
  }
}

/* action delegation */
content.addEventListener('click', (ev) => {
  const btn = ev.target.closest('button[data-action]');
  if(!btn) return;
  const action = btn.dataset.action;
  const id = btn.dataset.id;
  if(!action || !id) return;
  switch(action){
    case 'user': showUser(id); break;
    case 'group': showGroup(id); break;
    case 'role': showRole(id); break;
    case 'app': showApp(id); break;
    case 'sp': showSP(id); break;
    case 'device': showDevice(id); break;
    case 'au': showAU(id); break;
    default: console.warn('Unknown action', action);
  }
});

/* helper to render a member line with name + email/UPN */
function memberLine(displayName, upn, mail, id){
  let line = '<strong>'+escapeHtml(displayName || id || '')+'</strong>';
  const email = mail || upn || '';
  if(email) line += ' <span class="member-email">'+escapeHtml(email)+'</span>';
  else line += ' <span class="member-email">'+escapeHtml(id || '')+'</span>';
  return line;
}

/* detail viewers */
async function showUser(userId){
  const id = decodeURIComponent(userId);
  let detailContainer = document.getElementById('detail');
  if(!detailContainer){
    detailContainer = document.createElement('div'); detailContainer.id='detail'; document.querySelector('.content').appendChild(detailContainer);
  }
  detailContainer.innerHTML = '<div class="section">Loading user details...</div>';
  try{
    const j = await fetchJSON('/api/section/users/item/' + encodeURIComponent(id));
    const d = j.details;
    const u = d.user || {};
    let out = '<div class="section"><h3>'+escapeHtml(u.displayName || u.userPrincipalName || 'User')+'</h3>';
    out += '<div class="muted">id: '+escapeHtml(u.id || '')+' | UPN: '+escapeHtml(u.userPrincipalName || '')+'</div>';
    out += '<div class="muted">Enabled: '+escapeHtml(String(u.accountEnabled))+' | UserType: '+escapeHtml(u.userType||'')+' | Dept: '+escapeHtml(u.department||'')+'</div>';
    out += (u.onPremisesSyncEnabled ? '<div class="muted">Account source: On-premises (sync enabled)</div>' : '<div class="muted">Account source: Cloud</div>');
    if(d.lastPasswordChange) out += '<div class="muted">Last password change (best-effort): '+escapeHtml(d.lastPasswordChange)+'</div>';
    if(d.lastSignIn) out += '<div class="muted">Last sign-in (best-effort): '+escapeHtml(d.lastSignIn)+'</div>';

    // Groups
    out += '<div style="margin-top:10px"><strong>Groups</strong>';
    if(Array.isArray(d.groups) && d.groups.length){
      out += '<div class="muted">Member of '+d.groups.length+' group(s)</div><ul>';
      d.groups.forEach(g=>{
        const name = g.displayName || g.id || '';
        const email = g.mail || '';
        out += '<li>'+memberLine(name, '', email, g.id)+' <button class="btn" data-action="group" data-id="'+escapeHtml(g.id||'')+'">Open</button></li>';
      });
      out += '</ul>';
    } else if(d.memberOfError){
      out += '<div class="muted">Error fetching group membership: '+escapeHtml(d.memberOfError)+'</div>';
    } else {
      out += '<div class="muted">No group membership or cannot fetch groups.</div>';
    }
    out += '</div>';

    // Owned applications
    out += '<div style="margin-top:10px"><strong>Owned applications</strong>';
    if(Array.isArray(d.ownedApplications) && d.ownedApplications.length){
      out += '<div class="muted">Owns '+d.ownedApplications.length+' application(s)</div><ul>';
      d.ownedApplications.forEach(a=>{
        out += '<li><strong>'+escapeHtml(a.displayName||a.appId||a.id||'')+'</strong> <button class="btn" data-action="app" data-id="'+escapeHtml(a.id||'')+'">Open app</button></li>';
      });
      out += '</ul>';
    } else if(d.ownedObjectsError){
      out += '<div class="muted">Error fetching owned objects: '+escapeHtml(d.ownedObjectsError)+'</div>';
    } else {
      out += '<div class="muted">No owned applications.</div>';
    }
    out += '</div>';

    // Directory roles
    out += '<div style="margin-top:10px"><strong>Directory roles</strong>';
    if(Array.isArray(d.directoryRoles) && d.directoryRoles.length){
      out += '<ul>';
      d.directoryRoles.forEach(r=> out += '<li><strong>'+escapeHtml(r.displayName||'')+'</strong> <button class="btn" data-action="role" data-id="'+escapeHtml(r.id||'')+'">Open</button></li>');
      out += '</ul>';
    } else {
      out += '<div class="muted">No directory roles assigned.</div>';
    }
    out += '</div>';

    if(Array.isArray(d.unresolvedMemberOf) && d.unresolvedMemberOf.length){
      out += '<div style="margin-top:10px"><strong>Unresolved membership</strong><div class="muted">The UI attempted to resolve some objects but could not. This may be due to Graph permissions or missing objects.</div><ul>';
      d.unresolvedMemberOf.forEach(x => out += '<li>'+escapeHtml(x.id || JSON.stringify(x.raw || {}))+'</li>');
      out += '</ul></div>';
    }

    out += '<div style="margin-top:12px"><details><summary>Show raw user JSON</summary><pre>'+escapeHtml(JSON.stringify(u, null, 2))+'</pre></details></div>';
    out += '</div>';
    detailContainer.innerHTML = out;
    window.scrollTo(0, detailContainer.offsetTop);
  } catch (err){
    detailContainer.innerHTML = '<div class="section"><strong>Error:</strong> '+escapeHtml(String(err.message))+'</div>';
  }
}

function showGroup(id){
  fetch('/api/section/groups/item/' + encodeURIComponent(id)).then(r=>r.json()).then(j=>{
    const d=j.details; const g=d.group||{};
    let out='<div class="section"><h3>'+ escapeHtml(g.displayName||'Group') +'</h3>';
    out+='<div class="muted">id: '+escapeHtml(g.id||'')+' | mail: '+escapeHtml(g.mail||'')+'</div>';
    out+='<div style="margin-top:8px"><strong>Members ('+ (Array.isArray(d.members)? d.members.length : 'N/A') +')</strong>';
    if(Array.isArray(d.members)&&d.members.length){
      out+='<ul>';
      d.members.forEach(m=>{
        const name = m.displayName || m.userPrincipalName || m.id || '';
        const email = m.mail || m.userPrincipalName || '';
        out += '<li>'+memberLine(name, m.userPrincipalName||'', m.mail||'', m.id)+' <button class="btn" data-action="user" data-id="'+escapeHtml(m.id||'')+'">Open user</button></li>';
      });
      out+='</ul>';
    } else if(d.members && d.members.error) out+='<div class="muted">Error loading members: '+escapeHtml(d.members.error)+'</div>';
    else out+='<div class="muted">No members</div>';
    out+='</div>';
    out+='<div style="margin-top:12px"><details><summary>Show raw group JSON</summary><pre>'+escapeHtml(JSON.stringify(g, null, 2))+'</pre></details></div>';
    out+='</div>';
    document.getElementById('detail').innerHTML=out;
  }).catch(e=>document.getElementById('detail').innerHTML='<div class="section"><strong>Error:</strong>'+escapeHtml(e)+'</div>');
}

function showRole(id){
  fetch('/api/section/directoryRoles/item/' + encodeURIComponent(id)).then(r=>r.json()).then(j=>{
    const d=j.details; const r=d.role||{};
    let out='<div class="section"><h3>'+ escapeHtml(r.displayName||'Role') +'</h3>';
    out+='<div class="muted">id: '+escapeHtml(r.id||'')+'</div>';
    out+='<div style="margin-top:8px"><strong>Members ('+ (Array.isArray(d.members)? d.members.length : 'N/A') +')</strong>';
    if(Array.isArray(d.members)&&d.members.length){
      out+='<ul>';
      d.members.forEach(m=>{
        const name = m.displayName || m.userPrincipalName || m.id || '';
        const email = m.mail || m.userPrincipalName || '';
        out += '<li>'+memberLine(name, m.userPrincipalName||'', m.mail||'', m.id)+' <button class="btn" data-action="user" data-id="'+escapeHtml(m.id||'')+'">Open user</button></li>';
      });
      out+='</ul>';
    } else if(d.members && d.members.error) out+='<div class="muted">Error loading members: '+escapeHtml(d.members.error)+'</div>';
    else out+='<div class="muted">No members</div>';
    out+='</div>';
    out+='<div style="margin-top:12px"><details><summary>Show raw role JSON</summary><pre>'+escapeHtml(JSON.stringify(r, null, 2))+'</pre></details></div>';
    out+='</div>';
    document.getElementById('detail').innerHTML=out;
  }).catch(e=>document.getElementById('detail').innerHTML='<div class="section"><strong>Error:</strong>'+escapeHtml(e)+'</div>');
}

function showApp(id){
  fetch('/api/section/applications/item/' + encodeURIComponent(id)).then(r=>r.json()).then(j=>{
    const d=j.details; const a=d.application||{};
    let out='<div class="section"><h3>'+ escapeHtml(a.displayName||a.appId||'Application') +'</h3>';
    out+='<div class="muted">id: '+escapeHtml(a.id||'')+' | appId: '+escapeHtml(a.appId||'')+'</div>';
    if(a.signInAudience) out+='<div class="muted">signInAudience: '+escapeHtml(a.signInAudience)+'</div>';
    if(a.publisherDomain) out+='<div class="muted">publisherDomain: '+escapeHtml(a.publisherDomain)+'</div>';
    if(a.createdDateTime) out+='<div class="muted">created: '+escapeHtml(a.createdDateTime)+'</div>';
    out+='<div class="owners"><strong>Owners ('+ (Array.isArray(d.owners)? d.owners.length : 'N/A') +')</strong>';
    if(Array.isArray(d.owners) && d.owners.length){
      out+='<ul>';
      d.owners.forEach(o=>{
        const name = o.displayName || o.userPrincipalName || o.mail || o.id || '';
        const email = o.mail || o.userPrincipalName || '';
        out += '<li>'+memberLine(name, o.userPrincipalName||'', o.mail||'', o.id)+' ';
        if(o.objectType === 'user' || o.objectType === 'unknown') out += '<button class="btn" data-action="user" data-id="'+escapeHtml(o.id||'')+'">Open</button>';
        else if(o.objectType === 'servicePrincipal') out += '<button class="btn" data-action="sp" data-id="'+escapeHtml(o.id||'')+'">Open SP</button>';
        out += '</li>';
      });
      out+='</ul>';
    } else if(d.owners && d.owners.error) out+='<div class="muted">Error loading owners: '+escapeHtml(d.owners.error)+'</div>';
    else out+='<div class="muted">No owners</div>';
    out+='</div>';
    out+='<div style="margin-top:12px"><details><summary>Show raw application JSON</summary><pre>'+escapeHtml(JSON.stringify(a, null, 2))+'</pre></details></div>';
    out+='</div>';
    document.getElementById('detail').innerHTML=out;
  }).catch(e=>document.getElementById('detail').innerHTML='<div class="section"><strong>Error:</strong>'+escapeHtml(e)+'</div>');
}

function showSP(id){ fetch('/api/section/servicePrincipals/item/' + encodeURIComponent(id)).then(r=>r.json()).then(j=>{ const sp=j.details.servicePrincipal||{}; let out='<div class="section"><h3>'+ escapeHtml(sp.displayName||'Service Principal') +'</h3>'; out+='<div class="muted">id: '+escapeHtml(sp.id||'')+' | appId: '+escapeHtml(sp.appId||'')+'</div>'; out+='<div style="margin-top:12px"><details><summary>Show raw SP JSON</summary><pre>'+escapeHtml(JSON.stringify(sp,null,2))+'</pre></details></div></div>'; document.getElementById('detail').innerHTML=out; }).catch(e=>document.getElementById('detail').innerHTML='<div class="section"><strong>Error:</strong>'+escapeHtml(e)+'</div>'); }
function showDevice(id){ fetch('/api/section/devices/item/' + encodeURIComponent(id)).then(r=>r.json()).then(j=>{ const d=j.details.device||{}; let out='<div class="section"><h3>'+ escapeHtml(d.displayName||d.deviceId||'Device') +'</h3>'; out+='<div class="muted">id: '+escapeHtml(d.id||'')+' | deviceId: '+escapeHtml(d.deviceId||'')+'</div>'; if(Array.isArray(j.details.owners) && j.details.owners.length){ out+='<div style="margin-top:8px"><strong>Owners</strong><ul>'; j.details.owners.forEach(o=>{ const name=o.displayName||o.userPrincipalName||o.mail||o.id; const email=o.mail||o.userPrincipalName||''; out+='<li>'+memberLine(name,o.userPrincipalName||'',o.mail||'',o.id)+'</li>'; }); out+='</ul></div>'; } out+='<div style="margin-top:12px"><details><summary>Show raw device JSON</summary><pre>'+escapeHtml(JSON.stringify(d,null,2))+'</pre></details></div></div>'; document.getElementById('detail').innerHTML=out; }).catch(e=>document.getElementById('detail').innerHTML='<div class="section"><strong>Error:</strong>'+escapeHtml(e)+'</div>'); }
function showAU(id){ fetch('/api/section/administrativeUnits/item/' + encodeURIComponent(id)).then(r=>r.json()).then(j=>{ const au=j.details.administrativeUnit||{}; let out='<div class="section"><h3>'+ escapeHtml(au.displayName||'Administrative Unit') +'</h3>'; out+='<div class="muted">id: '+escapeHtml(au.id||'')+'</div>'; if(Array.isArray(j.details.members) && j.details.members.length){ out+='<div style="margin-top:8px"><strong>Members ('+j.details.members.length+')</strong><ul>'; j.details.members.forEach(m=>{ const name=m.displayName||m.userPrincipalName||m.id; const email=m.mail||m.userPrincipalName||''; out+='<li>'+memberLine(name,m.userPrincipalName||'',m.mail||'',m.id)+'</li>'; }); out+='</ul></div>'; } out+='<div style="margin-top:12px"><details><summary>Show raw AU JSON</summary><pre>'+escapeHtml(JSON.stringify(au,null,2))+'</pre></details></div></div>'; document.getElementById('detail').innerHTML=out; }).catch(e=>document.getElementById('detail').innerHTML='<div class="section"><strong>Error:</strong>'+escapeHtml(e)+'</div>'); }

function refreshSection(){ if(current) loadSection(current, true); }
function showRaw(){ if(!current) return; fetch('/api/section/'+current).then(r=>r.json()).then(j=>{ content.innerHTML = '<div class="section"><h3>Raw JSON</h3><pre>'+escapeHtml(JSON.stringify(j.summary||j.data, null, 2))+'</pre></div>'; }); }

buildNav();
const firstBtn = nav.querySelector('button[data-section]');
if(firstBtn) { selectSection(firstBtn.dataset.section, firstBtn); }
</script>
</body>
</html>
"""

# -------------------------
# CLI / Serve
# -------------------------
def main():
    p = argparse.ArgumentParser(prog="graphhunter", description="GraphHunter - final v8 (show name+email)")
    p.add_argument("--token", help="Graph API Bearer token (optional). If not provided you'll be prompted.")
    p.add_argument("--serve", action="store_true", help="Start local web UI (opens browser).")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", default=5000, type=int)
    p.add_argument("--no-open", action="store_true")
    args = p.parse_args()

    token = args.token
    if not token:
        try:
            token = input("Enter Graph API Bearer token: ").strip()
        except KeyboardInterrupt:
            print("No token provided. Exiting."); sys.exit(1)
    if not token:
        print("Token required. Exiting."); sys.exit(1)

    headers_test = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    try:
        tst = requests.get(f"{API_BASE}/me", headers=headers_test, timeout=8)
        if tst.status_code in (401,403):
            print("Warning: token returned", tst.status_code, "- it may be invalid or lack scopes. You can continue, but calls may fail.")
    except Exception:
        print("Warning: could not reach Graph to validate token (network). Proceeding; UI will show errors if requests fail.")

    if args.serve:
        print(f"Starting GraphHunter web UI at http://{args.host}:{args.port}/ (listening on {args.host}:{args.port})")
        try:
            print("[prefetch] fetching sections...")
            prefetch_all_sections(headers_test)
        except Exception as e:
            print("[prefetch] warning: some sections failed to prefetch:", e)
        app = create_app(token, host=args.host, port=args.port)
        if not args.no_open:
            try: webbrowser.open(f"http://{args.host}:{args.port}/")
            except Exception: pass
        app.run(host=args.host, port=args.port, debug=False, use_reloader=False)
    else:
        print("One-shot fetch: saving to files.")
        for s in SECTION_FETCHERS.keys():
            try:
                res = get_section_cached(s, headers_test, force_refresh=True)
                fname = f"{s}.json"
                with open(fname, "w", encoding="utf-8") as f:
                    json.dump(res["data"], f, indent=2, ensure_ascii=False)
                print(f"Saved {fname} ({len(res['data'])} items)")
            except Exception as e:
                print(f"[{s}] error: {e}")

if __name__ == "__main__":
    main()

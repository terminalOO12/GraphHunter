#!/usr/bin/env python3
"""
GraphHunter - Final (cleaned & hardened)

Usage:
    python3 graphhunter_final.py --token "<GRAPH_TOKEN>" --serve --port 1777

Notes:
- Writes per-section files into ./data and a combined file ./data/all_data.json.
- Exposes a Local AI endpoint that calls the `ollama` CLI (if present).
- UI includes a dedicated AI panel and robust rendering for service principals, devices, and administrative units.
"""
from typing import Dict, Any, List, Optional, Tuple
import argparse, requests, time, threading, json, webbrowser, sys, os, subprocess, traceback
from flask import Flask, jsonify, request, send_from_directory, Response
from pathlib import Path
from io import StringIO
import csv

API_BASE = "https://graph.microsoft.com/v1.0"
CACHE_TTL = 60.0
DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)

DEFAULT_OLLAMA_MODEL = "llama3.1:8b"
MAX_PROMPT_CHARS = 12000
MAX_SECTION_RETURN = 500

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

def get_all(endpoint: str, headers: Dict[str, Any]) -> List[Dict[str, Any]]:
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
        if isinstance(data, dict) and "value" in data and isinstance(data["value"], list):
            results.extend(data["value"])
            url = data.get("@odata.nextLink")
        else:
            if isinstance(data, dict):
                results.append(data)
            break
    return results

# -------------------------
# Section fetchers
# -------------------------
def fetch_users(headers):
    return get_all("users?$select=id,displayName,userPrincipalName,accountEnabled,userType,department,mail,onPremisesSyncEnabled,createdDateTime", headers)

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
    apps = get_all("applications?$select=id,displayName,createdDateTime,publisherDomain,signInAudience,appId", headers)
    out = []
    for a in apps:
        app_id = a.get("id")
        obj = {
            "id": app_id,
            "displayName": a.get("displayName"),
            "createdDateTime": a.get("createdDateTime"),
            "publisherDomain": a.get("publisherDomain"),
            "signInAudience": a.get("signInAudience"),
            "appId": a.get("appId"),
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
            print("[prefetch] section '{}' fetched ({} items).".format(s, len(res["data"])))
        except Exception as e:
            print("[prefetch] section '{}' failed: {}".format(s, e))
            with _cache_lock:
                _cache[s] = {"ts": time.time(), "data": []}

# -------------------------
# Deterministic resolvers and details
# -------------------------
def _resolve_group(id: str, headers: Dict[str,str]) -> Optional[Dict[str,Any]]:
    try:
        r = request_with_backoff(f"{API_BASE}/groups/{id}?$select=id,displayName,mail,groupTypes", headers)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None

def _resolve_user(id: str, headers: Dict[str,str]) -> Optional[Dict[str,Any]]:
    try:
        r = request_with_backoff(f"{API_BASE}/users/{id}?$select=id,displayName,userPrincipalName,mail", headers)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None

def _resolve_service_principal(id: str, headers: Dict[str,str]) -> Optional[Dict[str,Any]]:
    try:
        r = request_with_backoff(f"{API_BASE}/servicePrincipals/{id}?$select=id,displayName,appId", headers)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None

def _resolve_application(id: str, headers: Dict[str,str]) -> Optional[Dict[str,Any]]:
    try:
        r = request_with_backoff(f"{API_BASE}/applications/{id}?$select=id,displayName,appId", headers)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None

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

def fetch_group_detail(group_id: str, headers: Dict[str,str]):
    resp = request_with_backoff(f"{API_BASE}/groups/{group_id}", headers)
    group_obj = resp.json()
    members = []
    try:
        members = get_all(f"groups/{group_id}/members?$select=id,displayName,userPrincipalName,mail", headers)
    except Exception as e:
        members = {"error": str(e)}
    return {"group": group_obj, "members": members}

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

# Robust user detail
def fetch_user_detail_full(user_id: str, headers: Dict[str,str]):
    fields = "id,displayName,userPrincipalName,accountEnabled,userType,department,jobTitle,mobilePhone,officeLocation,createdDateTime,onPremisesSyncEnabled,onPremisesSamAccountName,mail,onPremisesLastPasswordSyncDateTime"
    try:
        resp = request_with_backoff(f"{API_BASE}/users/{user_id}?$select={fields}", headers)
    except Exception:
        resp = request_with_backoff(f"{API_BASE}/users/{user_id}", headers)
    user = {}
    try:
        user = resp.json()
    except Exception:
        user = {}

    member_of_raw = None
    member_of_error = None
    try:
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
            # try directory role
            try:
                rresp = request_with_backoff(f"{API_BASE}/directoryRoles/{mo_id}?$select=id,displayName", headers)
                if rresp.status_code == 200:
                    rr = rresp.json()
                    resolved_roles.append({"id": rr.get("id"), "displayName": rr.get("displayName") or rr.get("id")})
                    continue
            except Exception:
                pass
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
# Local LLM / Ollama helpers & combined dump
# -------------------------
def save_all_sections_to_disk(headers: Dict[str,str], force_refresh: bool = False) -> dict:
    out = {}
    all_data = {}
    for s in SECTION_FETCHERS.keys():
        try:
            res = get_section_cached(s, headers, force_refresh=force_refresh)
            path = DATA_DIR / f"{s}.json"
            with open(path, "w", encoding="utf-8") as f:
                json.dump(res["data"], f, indent=2, ensure_ascii=False)
            out[s] = str(path)
            all_data[s] = res["data"]
        except Exception as e:
            out[s] = "error: {}".format(e)
            all_data[s] = []
    # write combined file
    try:
        all_path = DATA_DIR / "all_data.json"
        with open(all_path, "w", encoding="utf-8") as f:
            json.dump(all_data, f, indent=2, ensure_ascii=False)
        out["all_data"] = str(all_path)
    except Exception as e:
        out["all_data"] = "error: {}".format(e)
    return out

def _load_all_records() -> dict:
    out = {}
    for s in SECTION_FETCHERS.keys():
        p = DATA_DIR / f"{s}.json"
        if p.exists():
            try:
                with open(p, "r", encoding="utf-8") as f:
                    out[s] = json.load(f)
            except Exception:
                out[s] = []
        else:
            with _cache_lock:
                ent = _cache.get(s)
                out[s] = ent["data"] if ent else []
    return out

def _simple_score_record(record: dict, query: str, fields: Tuple[str,...]=("displayName","userPrincipalName","mail","appId","publisherName")) -> int:
    q = (query or "").lower()
    score = 0
    for f in fields:
        v = record.get(f) if isinstance(record, dict) else None
        if isinstance(v, str):
            lv = v.lower()
            if q in lv:
                score += 10
                score += lv.count(q)
    try:
        txt = json.dumps(record).lower()
        if q in txt:
            score += 1
    except Exception:
        pass
    return score

ROLE_SYNONYMS = {
    "global admin": "global administrator",
    "global administrator": "global administrator",
    "global admins": "global administrator",
    "global administrators": "global administrator",
    "tenant admin": "global administrator",
    "company admin": "global administrator",
    "company administrator": "global administrator"
}

# -------------------------
# Retriever: improved, handles user queries specifically
# -------------------------
def retrieve_context(query: str, top_k: int = 8, headers: Dict[str,str]=None) -> Tuple[list, dict]:
    all_data = _load_all_records()
    q_lower = (query or "").strip().lower()

    for k, v in ROLE_SYNONYMS.items():
        if k in q_lower:
            q_lower = q_lower.replace(k, v)

    # direct list / show
    tokens = q_lower.split()
    if any(tok in tokens for tok in ("list", "show", "display", "give")):
        if "user" in q_lower:
            items = all_data.get("users", []) or []
            cap = min(len(items), MAX_SECTION_RETURN)
            return [("users", items[i]) for i in range(cap)], all_data
        if "group" in q_lower:
            items = all_data.get("groups", []) or []
            cap = min(len(items), MAX_SECTION_RETURN)
            return [("groups", items[i]) for i in range(cap)], all_data
        if "application" in q_lower or "app " in q_lower or "apps" in q_lower:
            items = all_data.get("applications", []) or []
            cap = min(len(items), MAX_SECTION_RETURN)
            return [("applications", items[i]) for i in range(cap)], all_data
        if "service principal" in q_lower:
            items = all_data.get("servicePrincipals", []) or []
            cap = min(len(items), MAX_SECTION_RETURN)
            return [("servicePrincipals", items[i]) for i in range(cap)], all_data
        if "role" in q_lower or "administrator" in q_lower:
            items = all_data.get("directoryRoles", []) or []
            cap = min(len(items), MAX_SECTION_RETURN)
            return [("directoryRoles", items[i]) for i in range(cap)], all_data

    # user lookup intent
    if "user" in q_lower or "@" in q_lower or len(q_lower.split()) <= 3:
        users = all_data.get("users", []) or []
        matched = []
        for u in users:
            dn = (u.get("displayName") or "").lower()
            upn = (u.get("userPrincipalName") or "").lower()
            mail = (u.get("mail") or "").lower()
            if q_lower == dn or q_lower == upn or q_lower == mail:
                matched.append(u)
            elif q_lower in dn or q_lower in upn or q_lower in mail:
                matched.append(u)
        if not matched:
            q_terms = [t for t in q_lower.split() if len(t) > 1]
            for u in users:
                dn = (u.get("displayName") or "").lower()
                if any(t in dn for t in q_terms):
                    matched.append(u)
        if matched:
            ctx = []
            for u in matched[:top_k]:
                uid = u.get("id")
                if uid and headers:
                    try:
                        det = fetch_user_detail_full(uid, headers)
                        entry = det.copy()
                        entry["id"] = uid
                        entry["displayName"] = det.get("user", {}).get("displayName") or u.get("displayName")
                        entry["userPrincipalName"] = det.get("user", {}).get("userPrincipalName") or u.get("userPrincipalName")
                        ctx.append(("users", entry))
                    except Exception:
                        ctx.append(("users", u))
                else:
                    ctx.append(("users", u))
            return ctx, all_data

    # application owners intent
    if any(k in q_lower for k in ("owner", "owners", "app owners", "application owners")):
        apps = all_data.get("applications", []) or []
        matched = []
        for a in apps:
            name = (a.get("displayName") or "").lower()
            appid = (a.get("appId") or "").lower()
            if name and name in q_lower:
                matched.append(a)
            elif appid and appid in q_lower:
                matched.append(a)
        if not matched:
            q_terms = [t for t in q_lower.split() if len(t) > 2]
            for a in apps:
                name = (a.get("displayName") or "").lower()
                if any(t in name for t in q_terms):
                    matched.append(a)
        ctx = []
        for a in matched[:top_k]:
            aid = a.get("id")
            if aid and headers:
                try:
                    det = fetch_application_detail(aid, headers)
                    entry = dict(a)
                    entry["owners"] = det.get("owners", [])
                    ctx.append(("applications", entry))
                except Exception:
                    ctx.append(("applications", a))
            else:
                ctx.append(("applications", a))
        if ctx:
            return ctx, all_data
        items = all_data.get("applications", []) or []
        cap = min(len(items), MAX_SECTION_RETURN)
        return [("applications", items[i]) for i in range(cap)], all_data

    # directory roles heuristic
    if any(tok in q_lower for tok in ("admin", "administrator", "role")):
        drs = all_data.get("directoryRoles", []) or []
        matches = []
        for dr in drs:
            name = (dr.get("displayName") or "").lower()
            if not name:
                continue
            if q_lower in name or any(token in name for token in q_lower.split()):
                matches.append(dr)
        for syn in set(ROLE_SYNONYMS.values()):
            if syn in q_lower:
                for dr in drs:
                    if syn in (dr.get("displayName") or "").lower():
                        matches.append(dr)
        if matches:
            seen = set()
            out = []
            for m in matches:
                rid = m.get("id")
                if rid and rid not in seen:
                    seen.add(rid)
                    out.append(("directoryRoles", m))
            return out, all_data

    # fallback scoring
    scored = []
    for section, items in all_data.items():
        if not isinstance(items, list):
            continue
        for item in items:
            score = _simple_score_record(item, q_lower)
            if score > 0:
                scored.append((score, section, item))
    scored.sort(reverse=True, key=lambda x: x[0])
    top = [(sec, rec) for _, sec, rec in scored[:top_k]]
    return top, all_data

# -------------------------
# Prompt building and calling LLM
# -------------------------
def _brief_record_for_prompt(rec: dict, redact: bool = False) -> dict:
    brief = {}
    for k in ("id","displayName","userPrincipalName","mail","appId","publisherName","groupTypes","createdDateTime","members_count","owners_count"):
        if k in rec:
            brief[k] = rec.get(k)
    if redact:
        if "mail" in brief:
            brief["mail"] = "[REDACTED]"
        if "userPrincipalName" in brief:
            brief["userPrincipalName"] = "[REDACTED]"
    return brief

def build_prompt_from_context(query: str, context_items: list, system_instructions: str = None, redact: bool = False) -> str:
    if system_instructions is None:
        system_instructions = (
            "You are a helpful local assistant that answers questions about an organization's Microsoft Entra/Graph data. "
            "Use only the supplied context to answer succinctly. If you do not know, say you don't know. "
            "Do not hallucinate emails or UPNs that are not in the context. Be mindful of sensitive data."
        )
    ctx_parts = []
    for sec, rec in context_items:
        brief = _brief_record_for_prompt(rec, redact=redact)
        try:
            part = "Section: {}\n{}".format(sec, json.dumps(brief, indent=2, ensure_ascii=False))
        except Exception:
            part = "Section: {}\n{}".format(sec, str(brief))
        if sec == "directoryRoles" and isinstance(rec.get("members"), list):
            members_short = []
            for m in rec.get("members")[:50]:
                members_short.append({
                    "id": m.get("id"),
                    "displayName": m.get("displayName"),
                    "userPrincipalName": m.get("userPrincipalName"),
                    "mail": m.get("mail")
                })
            try:
                part += "\nMembers (first {}):\n{}".format(len(members_short), json.dumps(members_short, indent=2, ensure_ascii=False))
            except Exception:
                part += "\nMembers: (could not serialize)"
        if sec == "applications" and isinstance(rec.get("owners"), list):
            owners_short = []
            for o in rec.get("owners")[:50]:
                owners_short.append({
                    "id": o.get("id"),
                    "displayName": o.get("displayName"),
                    "userPrincipalName": o.get("userPrincipalName"),
                    "mail": o.get("mail"),
                    "objectType": o.get("objectType")
                })
            try:
                part += "\nOwners (first {}):\n{}".format(len(owners_short), json.dumps(owners_short, indent=2, ensure_ascii=False))
            except Exception:
                part += "\nOwners: (could not serialize)"
        if sec == "users" and isinstance(rec.get("user"), dict):
            user = rec.get("user")
            try:
                part += "\nUser detail:\n{}".format(json.dumps({
                    "id": user.get("id"),
                    "displayName": user.get("displayName"),
                    "userPrincipalName": user.get("userPrincipalName"),
                    "mail": user.get("mail"),
                    "department": user.get("department"),
                    "userType": user.get("userType")
                }, indent=2, ensure_ascii=False))
            except Exception:
                pass
            if isinstance(rec.get("groups"), list):
                try:
                    part += "\nGroups ({}):\n{}".format(len(rec.get("groups")), json.dumps(rec.get("groups")[:50], indent=2, ensure_ascii=False))
                except Exception:
                    pass
            if isinstance(rec.get("directoryRoles"), list):
                try:
                    part += "\nDirectoryRoles ({}):\n{}".format(len(rec.get("directoryRoles")), json.dumps(rec.get("directoryRoles")[:50], indent=2, ensure_ascii=False))
                except Exception:
                    pass
            if isinstance(rec.get("ownedApplications"), list):
                try:
                    part += "\nOwnedApplications ({}):\n{}".format(len(rec.get("ownedApplications")), json.dumps(rec.get("ownedApplications")[:50], indent=2, ensure_ascii=False))
                except Exception:
                    pass
        ctx_parts.append(part)

    if ctx_parts:
        sep = "\n\n---\n\n"
        ctx_text = sep.join(ctx_parts)
    else:
        ctx_text = "(no relevant context found)"

    prompt = (
        "SYSTEM: {sys}\n\n"
        "CONTEXT:\n"
        "{ctx}\n\n"
        "USER QUESTION:\n"
        "{q}\n\n"
        "INSTRUCTIONS:\n"
        "- Answer concisely and reference which section (users/groups/applications/etc) you used.\n"
        "- If you were given only a subset of data, say so and indicate how to see more (e.g., refresh or increase top_k).\n"
        "- Avoid exposing extra PII beyond what's necessary to answer.\n"
    ).format(sys=system_instructions, ctx=ctx_text, q=query)

    if len(prompt) > MAX_PROMPT_CHARS:
        truncated = []
        total = 0
        for p in ctx_parts:
            pl = len(p)
            if total + pl > MAX_PROMPT_CHARS // 2:
                break
            truncated.append(p)
            total += pl
        sep = "\n\n---\n\n"
        truncated_text = sep.join(truncated) if truncated else "(no context kept due to size limit)"
        prompt = (
            "SYSTEM: {sys}\n\n"
            "CONTEXT (TRUNCATED):\n"
            "{ctx}\n\n"
            "USER QUESTION:\n"
            "{q}\n\n"
            "INSTRUCTIONS:\n"
            "- Context was truncated to fit token limits. Consider increasing top_k or refreshing data to include more records.\n"
        ).format(sys=system_instructions, ctx=truncated_text, q=query)
    return prompt

def call_local_ollama(prompt: str, model: str = DEFAULT_OLLAMA_MODEL, timeout: int = 60) -> Tuple[bool, str]:
    cmd = ["ollama", "run", model]
    try:
        proc = subprocess.run(cmd, input=prompt, capture_output=True, text=True, timeout=timeout)
        if proc.returncode != 0:
            return False, "ollama run failed (code {}): {}".format(proc.returncode, proc.stderr.strip())
        out = proc.stdout.strip() or proc.stderr.strip()
        return True, out
    except subprocess.TimeoutExpired:
        return False, "ollama run timed out"
    except FileNotFoundError:
        return False, "'ollama' CLI not found on PATH"
    except Exception as e:
        return False, "ERROR calling ollama: {}".format(e)

# -------------------------
# Flask app factory & API
# -------------------------
headers_global: Dict[str,str] = {}

def create_app(bearer_token: str, host="127.0.0.1", port=5000):
    global headers_global
    headers_global = {"Authorization": "Bearer {}".format(bearer_token), "Accept": "application/json"}
    app = Flask(__name__, static_folder=None)
    headers = headers_global

    @app.route("/asset/<path:filename>")
    def asset(filename):
        return send_from_directory("asset", filename)

    @app.route("/api/dump_all")
    def api_dump_all():
        p = DATA_DIR / "all_data.json"
        if not p.exists():
            try:
                save_all_sections_to_disk(headers, force_refresh=False)
            except Exception:
                pass
        if not p.exists():
            return jsonify({"error": "no combined dump available; refresh first"}), 404
        return send_from_directory(str(DATA_DIR), "all_data.json", as_attachment=True)

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
                try:
                    if section == "users":
                        summary = [{"id": u.get("id"), "displayName": u.get("displayName") or u.get("userPrincipalName"), "userPrincipalName": u.get("userPrincipalName"), "accountEnabled": u.get("accountEnabled"), "userType": u.get("userType"), "mail": u.get("mail")} for u in data]
                    elif section == "groups":
                        summary = [{"id": g.get("id"), "displayName": g.get("displayName"), "mail": g.get("mail"), "groupTypes": g.get("groupTypes", [])} for g in data]
                    elif section == "directoryRoles":
                        summary = [{"id": r.get("id"), "displayName": r.get("displayName"), "members_count": r.get("members_count")} for r in data]
                    elif section == "applications":
                        summary = [{"id": a.get("id"), "displayName": a.get("displayName"), "owners_count": a.get("owners_count"), "createdDateTime": a.get("createdDateTime"), "appId": a.get("appId")} for a in data]
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
                        try:
                            raw = data if isinstance(data, list) else []
                            rows = []
                            for au in raw:
                                aid = au.get("id") if isinstance(au, dict) else None
                                name = au.get("displayName") if isinstance(au, dict) else None
                                desc = au.get("description") if isinstance(au, dict) else None
                                # skip empty placeholder items
                                if not aid and not name and not desc:
                                    continue
                                rows.append({
                                    "id": aid or "",
                                    "displayName": name or "",
                                    "description": desc or ""
                                })
                            summary = rows
                        except Exception:
                            summary = []
                    else:
                        summary = data
                except Exception:
                    summary = []
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
                details = fetch_user_detail_full(item_id, headers)
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

    @app.route("/api/section/<section>/export")
    def api_section_export(section):
        if section not in SECTION_FETCHERS:
            return jsonify({"error": "unknown section"}), 404
        fmt = request.args.get("format", "csv").lower()
        force = request.args.get("refresh", "false").lower() in ("1","true","yes")
        try:
            res = get_section_cached(section, headers, force_refresh=force)
            data = res["data"]
            if fmt == "json":
                return jsonify({"section": section, "data": data, "fetched_at": res["fetched_at"]})
            si = StringIO()
            writer = csv.writer(si)
            if section == "users":
                writer.writerow(["id","displayName","userPrincipalName","accountEnabled","userType","department","mail"])
                for u in data:
                    writer.writerow([u.get("id"), u.get("displayName"), u.get("userPrincipalName"), u.get("accountEnabled"), u.get("userType"), u.get("department"), u.get("mail")])
            elif section == "groups":
                writer.writerow(["id","displayName","mail","groupTypes","securityEnabled","mailEnabled"])
                for g in data:
                    writer.writerow([g.get("id"), g.get("displayName"), g.get("mail"), ";".join(g.get("groupTypes") or []), g.get("securityEnabled"), g.get("mailEnabled")])
            elif section == "directoryRoles":
                writer.writerow(["id","displayName","members_count"])
                for r in data:
                    writer.writerow([r.get("id"), r.get("displayName"), r.get("members_count")])
            elif section == "applications":
                writer.writerow(["id","displayName","appId","createdDateTime","owners_count","publisherDomain"])
                for a in data:
                    writer.writerow([a.get("id"), a.get("displayName"), a.get("appId"), a.get("createdDateTime"), a.get("owners_count"), a.get("publisherDomain")])
            elif section == "servicePrincipals":
                writer.writerow(["id","displayName","appId","publisherName"])
                for s in data:
                    writer.writerow([s.get("id"), s.get("displayName"), s.get("appId"), s.get("publisherName")])
            else:
                if not data:
                    writer.writerow(["empty"])
                else:
                    keys = sorted({k for item in data for k in (item.keys() if isinstance(item, dict) else [])})
                    writer.writerow(keys)
                    for item in data:
                        writer.writerow([item.get(k) if isinstance(item, dict) else "" for k in keys])
            output = si.getvalue()
            return Response(output, mimetype="text/csv", headers={"Content-Disposition": "attachment; filename={}.csv".format(section)})
        except Exception as e:
            return jsonify({"error":"export_failed","detail": str(e)}), 500

    @app.route("/api/check_scopes")
    def api_check_scopes():
        tests = {
            "users": (f"{API_BASE}/users?$top=1", "User.Read.All"),
            "groups": (f"{API_BASE}/groups?$top=1", "Group.Read.All"),
            "applications": (f"{API_BASE}/applications?$top=1", "Application.Read.All"),
            "directoryRoles": (f"{API_BASE}/directoryRoles?$top=1", "Directory.Read.All or RoleManagement.Read.Directory"),
            "auditLogs": (f"{API_BASE}/auditLogs/directoryAudits?$top=1", "AuditLog.Read.All")
        }
        results = {}
        for k,(u,hint) in tests.items():
            try:
                r = request_with_backoff(u, headers)
                results[k] = {"ok": r.status_code == 200, "status": r.status_code, "hint": hint}
            except Exception as e:
                results[k] = {"ok": False, "status": None, "hint": hint, "error": str(e)}
        return jsonify({"tests": results})

    @app.route("/api/local_query", methods=["POST"])
    def api_local_query():
        body = request.get_json(force=True, silent=True) or {}
        q = (body.get("q") or request.args.get("q") or "").strip()
        model = (body.get("model") or request.args.get("model") or DEFAULT_OLLAMA_MODEL).strip()
        top_k = int(body.get("top_k") or request.args.get("top_k") or 8)
        force_refresh = body.get("refresh", False) or request.args.get("refresh", "false").lower() in ("1","true","yes")
        redact = body.get("redact", False) or request.args.get("redact", "false").lower() in ("1","true","yes")
        debug = body.get("debug", False) or request.args.get("debug", "false").lower() in ("1","true","yes")
        if not q:
            return jsonify({"error": "missing query"}), 400

        try:
            save_all_sections_to_disk(headers, force_refresh=force_refresh)
        except Exception:
            pass

        q_lower = q.lower()
        # short-circuit list requests
        if any(q_lower.startswith(prefix) for prefix in ("list ", "show ", "display ", "give ")):
            for sec in SECTION_FETCHERS.keys():
                if sec in q_lower or sec.replace("administrativeUnits", "administrative unit") in q_lower or sec.replace("servicePrincipals","service principal") in q_lower:
                    try:
                        res = get_section_cached(sec, headers, force_refresh=force_refresh)
                        data = res["data"] or []
                        if sec == "users":
                            out = [{"id": u.get("id"), "displayName": u.get("displayName"), "upn": u.get("userPrincipalName"), "mail": u.get("mail")} for u in data[:MAX_SECTION_RETURN]]
                        elif sec == "applications":
                            out = [{"id": a.get("id"), "displayName": a.get("displayName"), "appId": a.get("appId"), "owners_count": a.get("owners_count")} for a in data[:MAX_SECTION_RETURN]]
                        elif sec == "groups":
                            out = [{"id": g.get("id"), "displayName": g.get("displayName"), "mail": g.get("mail")} for g in data[:MAX_SECTION_RETURN]]
                        elif sec == "servicePrincipals":
                            out = [{"id": s.get("id"), "displayName": s.get("displayName"), "appId": s.get("appId")} for s in data[:MAX_SECTION_RETURN]]
                        elif sec == "devices":
                            rows = []
                            for d in data[:MAX_SECTION_RETURN]:
                                os_name = d.get("operatingSystem") or ""
                                ver = d.get("operatingSystemVersion") or ""
                                os_full = (os_name + (" " + ver if ver else "")).strip()
                                if not os_full:
                                    os_full = d.get("deviceTrustType") or d.get("trustType") or ""
                                rows.append({"id": d.get("id"), "displayName": d.get("displayName"), "deviceId": d.get("deviceId"), "os": os_full})
                            out = rows
                        else:
                            out = data[:MAX_SECTION_RETURN]
                        return jsonify({"query": q, "section": sec, "count": len(data), "items": out})
                    except Exception as e:
                        return jsonify({"error": "failed_fetch_section", "detail": str(e)}), 500
            if "owner" in q_lower:
                pass

        try:
            ctx_pairs, all_data = retrieve_context(q, top_k=top_k, headers=headers)
            enriched = []
            for sec, rec in ctx_pairs:
                if sec == "directoryRoles":
                    rid = rec.get("id")
                    if rid:
                        try:
                            detail = fetch_role_detail(rid, headers)
                            rec = rec.copy()
                            rec["members"] = detail.get("members", [])
                        except Exception:
                            pass
                if sec == "applications":
                    aid = rec.get("id")
                    if aid:
                        try:
                            detail = fetch_application_detail(aid, headers)
                            rec = rec.copy()
                            rec["owners"] = detail.get("owners", [])
                        except Exception:
                            pass
                enriched.append((sec, rec))

            if not enriched:
                prompt = build_prompt_from_context(q, [], redact=redact)
                ok, out = call_local_ollama(prompt, model=model)
                resp = {"query": q, "model": model, "context": [], "ok": ok}
                if ok:
                    resp["response"] = out
                else:
                    resp["error"] = out
                if debug:
                    resp["prompt"] = prompt
                return jsonify(resp) if ok else (jsonify(resp), 500)

            prompt = build_prompt_from_context(q, enriched, redact=redact)
            ok, out = call_local_ollama(prompt, model=model)

            ctx_summary = []
            for sec, rec in enriched:
                label = rec.get("displayName") or rec.get("userPrincipalName") or rec.get("mail") or rec.get("appId") or rec.get("id")
                e = {"section": sec, "id": rec.get("id"), "displayName": label}
                if sec == "directoryRoles" and isinstance(rec.get("members"), list):
                    e["members_shown"] = len(rec.get("members"))
                if sec == "applications" and isinstance(rec.get("owners"), list):
                    e["owners_shown"] = len(rec.get("owners"))
                if sec == "users" and isinstance(rec.get("groups"), list):
                    e["groups_shown"] = len(rec.get("groups"))
                ctx_summary.append(e)

            payload = {"query": q, "model": model, "context": ctx_summary, "ok": ok}
            if ok:
                payload["response"] = out
            else:
                payload["error"] = out

            if debug:
                dbg = []
                for sec, rec in enriched:
                    snippet = dict(rec) if isinstance(rec, dict) else str(rec)
                    if sec == "directoryRoles" and isinstance(snippet.get("members"), list):
                        snippet["members"] = snippet["members"][:200]
                    if sec == "applications" and isinstance(snippet.get("owners"), list):
                        snippet["owners"] = snippet["owners"][:200]
                    if sec == "users":
                        if isinstance(snippet.get("groups"), list):
                            snippet["groups"] = snippet["groups"][:200]
                        if isinstance(snippet.get("ownedApplications"), list):
                            snippet["ownedApplications"] = snippet["ownedApplications"][:200]
                    dbg.append({"section": sec, "record": snippet})
                payload["debug_context"] = dbg
                payload["prompt"] = prompt

            return jsonify(payload) if ok else (jsonify(payload), 500)
        except Exception as e:
            return jsonify({"error": "internal", "detail": str(e), "trace": traceback.format_exc()}), 500

    @app.route("/")
    def index():
        return INDEX_HTML

    return app

# -------------------------
# Single-page client (HTML/JS)
# -------------------------
# NOTE: keep this a raw string (r"""...""") to avoid backslash parsing issues
INDEX_HTML = r"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>GraphHunter + Local AI</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>
    :root{--bg:#eaf4fb;--card:#fff;--muted:#6b7280}
    body{font-family:Inter,Helvetica,Arial,sans-serif;background:var(--bg);margin:0;padding:18px;min-height:100vh}
    .wrap{max-width:1200px;margin:0 auto}
    header{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px}
    h1{margin:0;font-size:32px}
    .subtitle{font-size:13px;color:#374151;margin-top:2px}
    .topbar{display:flex;gap:10px;align-items:center}
    .btn{padding:8px 12px;border-radius:8px;border:1px solid #e6e8ee;background:var(--card);cursor:pointer}
    .nav{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}
    .section{background:var(--card);padding:14px;border-radius:12px;box-shadow:0 8px 24px rgba(16,24,40,0.06);margin-bottom:12px}
    .muted{color:var(--muted);font-size:13px}
    .mini{font-size:13px;color:#374151}
    .ai-panel{display:grid;grid-template-columns:1fr 420px;gap:12px}
    input[type="text"], textarea{padding:10px;border-radius:10px;border:1px solid #e6e8ee;width:100%;box-sizing:border-box}
    textarea{min-height:120px;resize:vertical}
    .result-card{padding:12px;border-radius:10px;background:#f8fbff}
    table{width:100%;border-collapse:collapse}
    th,td{padding:8px;border-bottom:1px solid #f3f4f6;text-align:left;vertical-align:top}
    .chips{display:flex;gap:6px;flex-wrap:wrap}
    .chip{background:#eef2ff;padding:6px 8px;border-radius:999px;font-size:12px;color:#0f172a;cursor:pointer}
    details summary{cursor:pointer}
  </style>
</head>
<body>
<div class="wrap">
  <header>
    <div>
      <h1>GraphHunter</h1>
      <div class="subtitle">Developed By - Saksham Agrawal</div>
    </div>
    <div class="topbar">
      <div id="status" class="muted" style="display:none"></div>
      <button id="refreshAll" class="btn">Refresh all</button>
      <button id="checkScopes" class="btn">Check scopes</button>
      <a href="/api/dump_all" class="btn">Download combined JSON</a>
    </div>
  </header>

  <div class="nav" id="nav"></div>

  <div class="section ai-panel">
    <div>
      <h3>GraphHunter Intelligence Core</h3>
      <div class="muted">Ask questions about your tenant — everything stays local.</div>
      <div style="margin-top:8px;display:flex;gap:8px;align-items:center">
        <input id="llmQuery" placeholder="E.g., Who are the global administrators? List users. Who is 'Saksham'?" />
        <button id="llmBtn" class="btn">Ask</button>
      </div>
      <div style="margin-top:8px;display:flex;gap:12px;align-items:center">
        <label><input type="checkbox" id="redactToggle" /> Redact emails/UPNs</label>
        <label><input type="checkbox" id="refreshToggle" /> Force refresh</label>
        <label><input type="checkbox" id="debugToggle" /> Debug</label>
        <select id="modelSelect" style="margin-left:auto;padding:8px;border-radius:8px;border:1px solid #e6e8ee">
          <option value="llama3.1:8b">llama3.1:8b</option>
        </select>
      </div>

      <div id="llmResp" style="margin-top:12px"></div>
    </div>

    <div>
      <h3>Quick actions</h3>
      <div class="result-card">
        <div class="chips" style="margin-bottom:8px">
          <div class="chip" onclick="setSample('list users')">list users</div>
          <div class="chip" onclick="setSample('list applications')">list applications</div>
          <div class="chip" onclick="setSample('list application owners <app-name>')">list app owners</div>
          <div class="chip" onclick="setSample('who are the global administrators')">global admins</div>
          <div class="chip" onclick="setSample('show user saksham')">show user</div>
        </div>
        <div class="muted">Use Debug to inspect prompt & context. Use Redact for safe logs.</div>
      </div>

      <h3 style="margin-top:12px">Context quick view</h3>
      <div id="contextQuick" class="result-card muted">No recent query</div>
    </div>
  </div>

  <div id="content" class="content"><div class="section"><em>Use the nav to browse sections. Click a user to see enriched details on the right in the AI panel when you query a user.</em></div></div>
</div>

<script>
const SECTIONS = ["users","groups","directoryRoles","applications","servicePrincipals","devices","administrativeUnits"];
const DISPLAY = {"users":"Users","groups":"Groups","directoryRoles":"Directory roles","applications":"Applications","servicePrincipals":"Service principals","devices":"Devices","administrativeUnits":"Administrative units"};
const nav = document.getElementById('nav'), content = document.getElementById('content'), status = document.getElementById('status');

function setStatus(t){ if(status){ status.style.display='block'; status.textContent = "Status: "+t; } }
function escapeHtml(t){ return String(t||'').replace(/[&<>"']/g, m=> ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[m]); }

function buildNav(){
  SECTIONS.forEach(s=>{
    const b=document.createElement('button'); b.className='btn'; b.dataset.section=s; b.textContent=DISPLAY[s]||s;
    b.addEventListener('click', ()=> loadSection(s));
    nav.appendChild(b);
  });
}
async function fetchJSON(url){
  setStatus('fetching');
  const r = await fetch(url);
  setStatus('idle');
  if(!r.ok){
    let body={};
    try{ body = await r.json(); }catch(e){}
    throw new Error(body && body.error ? JSON.stringify(body) : 'HTTP '+r.status);
  }
  return r.json();
}

function setSample(text){ document.getElementById('llmQuery').value = text; }

async function loadSection(section, summary=true){
  content.innerHTML = '<div class="section">Loading '+escapeHtml(section)+' ...</div>';
  try {
    const j = await fetchJSON('/api/section/'+encodeURIComponent(section) + (summary? '' : '?summary=false'));
    const summaryList = j.summary || j.data || [];
    let html = '';
    if(section === 'users'){
      if(!summaryList || summaryList.length===0) html = '<div class="section"><h3>Users (0)</h3><div class="muted">No users found</div></div>';
      else{
        html = '<div class="section"><h3>Users ('+summaryList.length+')</h3><table><thead><tr><th>User</th><th>UPN</th><th>Action</th></tr></thead><tbody>';
        summaryList.forEach(u=>{
          html += '<tr>';
          html += '<td><strong>'+escapeHtml(u.displayName||'')+'</strong></td>';
          html += '<td class="mini"><pre>'+escapeHtml(u.userPrincipalName||u.upn||'')+'</pre></td>';
          html += '<td><button class="btn" data-action="user" data-id="'+escapeHtml(u.id||'')+'">Details</button></td>';
          html += '</tr>';
        });
        html += '</tbody></table></div><div id="detail"></div>';
      }
    } else if(section === 'groups'){
      if(!summaryList || summaryList.length===0) html = '<div class="section"><h3>Groups (0)</h3><div class="muted">No groups found</div></div>';
      else{
        html = '<div class="section"><h3>Groups ('+summaryList.length+')</h3><table><thead><tr><th>Group</th><th>Type</th><th>Action</th></tr></thead><tbody>';
        summaryList.forEach(g=>{
          const type = (g.groupTypes && g.groupTypes.length)? g.groupTypes.join(', ') : '';
          html += '<tr>';
          html += '<td><strong>'+escapeHtml(g.displayName||'')+'</strong><div class="muted">'+escapeHtml(g.mail || '')+'</div></td>';
          html += '<td class="mini">'+escapeHtml(String(type))+'</td>';
          html += '<td><button class="btn" data-action="group" data-id="'+escapeHtml(g.id||'')+'">Members</button></td>';
          html += '</tr>';
        });
        html += '</tbody></table></div><div id="detail"></div>';
      }
    } else if(section === 'directoryRoles'){
      html = '<div class="section"><h3>Directory roles ('+summaryList.length+')</h3><table><thead><tr><th>Role</th><th>Assigned</th><th>Action</th></tr></thead><tbody>';
      summaryList.forEach(r=>{
        html += '<tr>';
        html += '<td><strong>'+escapeHtml(r.displayName||'')+'</strong></td>';
        html += '<td class="mini">'+(r.members_count===null? 'N/A' : escapeHtml(String(r.members_count)))+'</td>';
        html += '<td><button class="btn" data-action="role" data-id="'+escapeHtml(r.id||'')+'">View members</button></td>';
        html += '</tr>';
      });
      html += '</tbody></table></div><div id="detail"></div>';
    } else if(section === 'applications'){
      html = '<div class="section"><h3>Applications ('+summaryList.length+')</h3><table><thead><tr><th>Name</th><th>Owners</th><th>Created</th><th>Action</th></tr></thead><tbody>';
      summaryList.forEach(a=>{
        html += '<tr>';
        html += '<td><strong>'+escapeHtml(a.displayName||'')+'</strong></td>';
        html += '<td class="mini">'+(a.owners_count===null? 'N/A' : escapeHtml(String(a.owners_count)))+'</td>';
        html += '<td class="mini">'+escapeHtml(a.createdDateTime||'')+'</td>';
        html += '<td><button class="btn" data-action="app" data-id="'+escapeHtml(a.id||'')+'">Details</button></td>';
        html += '</tr>';
      });
      html += '</tbody></table></div><div id="detail"></div>';
    } else if(section === 'servicePrincipals'){
      if(!summaryList || summaryList.length===0) html = '<div class="section"><h3>Service principals (0)</h3><div class="muted">No items</div></div>';
      else {
        html = '<div class="section"><h3>Service principals ('+summaryList.length+')</h3><table><thead><tr><th>Name</th><th>AppId</th><th>Action</th></tr></thead><tbody>';
        summaryList.forEach(s=>{
          html += '<tr>';
          html += '<td><strong>'+escapeHtml(s.displayName || s.appId || s.id || '')+'</strong></td>';
          html += '<td class="mini"><pre>'+escapeHtml(s.appId || '')+'</pre></td>';
          html += '<td><button class="btn" data-action="sp" data-id="'+escapeHtml(s.id||'')+'">Details</button></td>';
          html += '</tr>';
        });
        html += '</tbody></table></div><div id="detail"></div>';
      }
    } else if(section === 'devices'){
      if(!summaryList || summaryList.length===0) html = '<div class="section"><h3>Devices (0)</h3><div class="muted">No devices</div></div>';
      else {
        html = '<div class="section"><h3>Devices ('+summaryList.length+')</h3><table><thead><tr><th>Name</th><th>DeviceId</th><th>OS</th><th>Action</th></tr></thead><tbody>';
        summaryList.forEach(d=>{
          const os = d.os || (d.operatingSystem ? d.operatingSystem + (d.operatingSystemVersion ? (" " + d.operatingSystemVersion) : "") : (d.deviceTrustType || d.trustType || ''));
          html += '<tr>';
          html += '<td><strong>'+escapeHtml(d.displayName || d.deviceId || '')+'</strong></td>';
          html += '<td class="mini"><pre>'+escapeHtml(d.deviceId || '')+'</pre></td>';
          html += '<td class="mini">'+escapeHtml(os)+'</td>';
          html += '<td><button class="btn" data-action="device" data-id="'+escapeHtml(d.id||'')+'">Details</button></td>';
          html += '</tr>';
        });
        html += '</tbody></table></div><div id="detail"></div>';
      }
    } else if(section === 'administrativeUnits'){
      if(!summaryList || summaryList.length===0) html = '<div class="section"><h3>Administrative units (0)</h3><div class="muted">No administrative units</div></div>';
      else {
        html = '<div class="section"><h3>Administrative units ('+summaryList.length+')</h3><table><thead><tr><th>Name</th><th>Description</th><th>Action</th></tr></thead><tbody>';
        summaryList.forEach(a=>{
          html += '<tr>';
          html += '<td><strong>'+escapeHtml(a.displayName || a.id || '')+'</strong></td>';
          html += '<td class="mini">'+escapeHtml(a.description || '')+'</td>';
          html += '<td><button class="btn" data-action="au" data-id="'+escapeHtml(a.id||'')+'">Details</button></td>';
          html += '</tr>';
        });
        html += '</tbody></table></div><div id="detail"></div>';
      }
    } else {
      html = '<div class="section"><pre>'+escapeHtml(JSON.stringify(summaryList.slice(0,100), null, 2))+'</pre></div>';
    }
    html = '<div class="section"><button class="btn" id="refreshBtn">Refresh</button> <button class="btn" id="rawBtn">Show raw JSON</button> <button class="btn" id="downloadCsvBtn">Download CSV</button></div>' + html;
    content.innerHTML = html;
    document.getElementById('refreshBtn')?.addEventListener('click', ()=> loadSection(section, true));
    document.getElementById('rawBtn')?.addEventListener('click', ()=> { fetch('/api/section/'+section).then(r=>r.json()).then(j=>{ content.innerHTML = '<div class="section"><h3>Raw JSON</h3><pre>'+escapeHtml(JSON.stringify(j.summary||j.data, null, 2))+'</pre></div>'; }); });
    document.getElementById('downloadCsvBtn')?.addEventListener('click', ()=> { window.location = '/api/section/'+encodeURIComponent(section)+'/export?format=csv'; });
    window.scrollTo(0,0);
  } catch (err) {
    content.innerHTML = '<div class="section"><strong>Error:</strong> '+escapeHtml(String(err.message))+'</div>';
  }
}

buildNav();

document.getElementById('refreshAll').addEventListener('click', async ()=>{
  setStatus('Refreshing...');
  try{
    await fetch('/api/section/users?refresh=true');
    await fetch('/api/section/groups?refresh=true');
    await fetch('/api/section/applications?refresh=true');
    await fetch('/api/section/servicePrincipals?refresh=true');
    await fetch('/api/section/devices?refresh=true');
    await fetch('/api/section/administrativeUnits?refresh=true');
    setStatus('Refreshed.');
  }catch(e){ setStatus('Refresh failed: '+e); }
});

document.getElementById('checkScopes').addEventListener('click', async ()=>{
  setStatus('Checking scopes...');
  try{
    const r = await fetch('/api/check_scopes'); const j = await r.json();
    alert('Scope check:\\n'+JSON.stringify(j.tests,null,2));
    setStatus('Scope check done.');
  }catch(e){ setStatus('Scope check failed: '+e); }
});

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
    const d = j.details; const u = d.user || {};
    let out = '<div class="section"><h3>'+escapeHtml(u.displayName || u.userPrincipalName || 'User')+'</h3>';
    out += '<div class="muted">id: '+escapeHtml(u.id || '')+' | UPN: '+escapeHtml(u.userPrincipalName || '')+'</div>';
    out += '<div class="muted">Enabled: '+escapeHtml(String(u.accountEnabled))+' | UserType: '+escapeHtml(u.userType||'')+' | Dept: '+escapeHtml(u.department||'')+'</div>';
    if(d.lastPasswordChange) out += '<div class="muted">Last password change: '+escapeHtml(d.lastPasswordChange)+'</div>';
    if(d.lastSignIn) out += '<div class="muted">Last sign-in: '+escapeHtml(d.lastSignIn)+'</div>';

    out += '<div style="margin-top:10px"><strong>Groups</strong>';
    if(Array.isArray(d.groups) && d.groups.length){
      out += '<div class="muted">Member of '+d.groups.length+' group(s)</div><ul>';
      d.groups.forEach(g=>{
        out += '<li><strong>'+escapeHtml(g.displayName||g.id||'')+'</strong> <span class="mini">'+escapeHtml(g.mail||'')+'</span></li>';
      });
      out += '</ul>';
    } else if(d.memberOfError){
      out += '<div class="muted">Error fetching group membership: '+escapeHtml(d.memberOfError)+'</div>';
    } else {
      out += '<div class="muted">No group membership or cannot fetch groups.</div>';
    }
    out += '</div>';

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

    out += '<div style="margin-top:10px"><strong>Directory roles</strong>';
    if(Array.isArray(d.directoryRoles) && d.directoryRoles.length){
      out += '<ul>';
      d.directoryRoles.forEach(r=> out += '<li><strong>'+escapeHtml(r.displayName||'')+'</strong></li>');
      out += '</ul>';
    } else {
      out += '<div class="muted">No directory roles assigned.</div>';
    }
    out += '</div>';

    if(Array.isArray(d.unresolvedMemberOf) && d.unresolvedMemberOf.length){
      out += '<div style="margin-top:10px"><strong>Unresolved membership</strong><div class="muted">Some objects could not be resolved. This may be due to Graph permissions.</div><ul>';
      d.unresolvedMemberOf.forEach(x => out += '<li>'+escapeHtml(x.id || JSON.stringify(x.raw || {}))+'</li>');
      out += '</ul></div>';
    }

    out += '<div style="margin-top:12px"><details><summary>Show raw user JSON</summary><pre>'+escapeHtml(JSON.stringify(u, null, 2))+'</pre></details></div>';
    out += '</div>';
    detailContainer.innerHTML = out;

    document.getElementById('contextQuick').textContent = 'Last queried user: ' + (u.displayName || u.userPrincipalName || u.id || '');
    window.scrollTo(0, detailContainer.offsetTop);
  } catch (err){
    detailContainer.innerHTML = '<div class="section"><strong>Error:</strong> '+escapeHtml(String(err.message))+'</div>';
  }
}

function showGroup(id){
  fetch('/api/section/groups/item/' + encodeURIComponent(id)).then(r=>r.json()).then(j=>{ const d=j.details; const g=d.group||{}; let out='<div class="section"><h3>'+ escapeHtml(g.displayName||'Group') +'</h3>'; out+='<div class="muted">id: '+escapeHtml(g.id||'')+' | mail: '+escapeHtml(g.mail||'')+'</div>'; out+='<div style="margin-top:8px"><strong>Members ('+ (Array.isArray(d.members)? d.members.length : 'N/A') +')</strong>'; if(Array.isArray(d.members)&&d.members.length){ out+='<ul>'; d.members.forEach(m=>{ const name = m.displayName || m.userPrincipalName || m.id || ''; const email = m.mail || m.userPrincipalName || ''; out += '<li><strong>'+escapeHtml(name)+'</strong> <span class="mini">'+escapeHtml(email)+'</span> <button class="btn" data-action="user" data-id="'+escapeHtml(m.id||'')+'">Open user</button></li>'; }); out+='</ul>'; } else if(d.members && d.members.error) out+='<div class="muted">Error loading members: '+escapeHtml(d.members.error)+'</div>'; else out+='<div class="muted">No members</div>'; out+='</div>'; out+='<div style="margin-top:12px"><details><summary>Show raw group JSON</summary><pre>'+escapeHtml(JSON.stringify(g, null, 2))+'</pre></details></div>'; out+='</div>'; document.getElementById('detail').innerHTML=out; }).catch(e=>document.getElementById('detail').innerHTML='<div class="section"><strong>Error:</strong>'+escapeHtml(e)+'</div>');
}

function showRole(id){
  fetch('/api/section/directoryRoles/item/' + encodeURIComponent(id)).then(r=>r.json()).then(j=>{ const d=j.details; const r=d.role||{}; let out='<div class="section"><h3>'+ escapeHtml(r.displayName||'Role') +'</h3>'; out+='<div class="muted">id: '+escapeHtml(r.id||'')+'</div>'; out+='<div style="margin-top:8px"><strong>Members ('+ (Array.isArray(d.members)? d.members.length : 'N/A') +')</strong>'; if(Array.isArray(d.members)&&d.members.length){ out+='<ul>'; d.members.forEach(m=>{ const name = m.displayName || m.userPrincipalName || m.id || ''; const email = m.mail || m.userPrincipalName || ''; out += '<li><strong>'+escapeHtml(name)+'</strong> <span class="mini">'+escapeHtml(email)+'</span> <button class="btn" data-action="user" data-id="'+escapeHtml(m.id||'')+'">Open</button></li>'; }); out+='</ul>'; } else if(d.members && d.members.error) out+='<div class="muted">Error loading members: '+escapeHtml(d.members.error)+'</div>'; else out+='<div class="muted">No members</div>'; out+='</div>'; out+='<div style="margin-top:12px"><details><summary>Show raw role JSON</summary><pre>'+escapeHtml(JSON.stringify(r, null, 2))+'</pre></details></div>'; out+='</div>'; document.getElementById('detail').innerHTML=out; }).catch(e=>document.getElementById('detail').innerHTML='<div class="section"><strong>Error:</strong>'+escapeHtml(e)+'</div>');
}

function showApp(id){ fetch('/api/section/applications/item/' + encodeURIComponent(id)).then(r=>r.json()).then(j=>{ const d=j.details; const a=d.application||{}; let out='<div class="section"><h3>'+ escapeHtml(a.displayName||a.appId||'Application') +'</h3>'; out+='<div class="muted">id: '+escapeHtml(a.id||'')+' | appId: '+escapeHtml(a.appId||'')+'</div>'; if(a.signInAudience) out+='<div class="muted">signInAudience: '+escapeHtml(a.signInAudience)+'</div>'; if(a.publisherDomain) out+='<div class="muted">publisherDomain: '+escapeHtml(a.publisherDomain)+'</div>'; if(a.createdDateTime) out+='<div class="muted">created: '+escapeHtml(a.createdDateTime)+'</div>'; out+='<div class="owners"><strong>Owners ('+ (Array.isArray(d.owners)? d.owners.length : 'N/A') +')</strong>'; if(Array.isArray(d.owners) && d.owners.length){ out+='<ul>'; d.owners.forEach(o=>{ const name = o.displayName || o.userPrincipalName || o.mail || o.id || ''; const email = o.mail || o.userPrincipalName || ''; out += '<li><strong>'+escapeHtml(name)+'</strong> <span class="mini">'+escapeHtml(email)+'</span> '; if(o.objectType === 'user' || o.objectType === 'unknown') out += '<button class="btn" data-action="user" data-id="'+escapeHtml(o.id||'')+'">Open</button>'; else if(o.objectType === 'servicePrincipal') out += '<button class="btn" data-action="sp" data-id="'+escapeHtml(o.id||'')+'">Open SP</button>'; out += '</li>'; }); out+='</ul>'; } else if(d.owners && d.owners.error) out+='<div class="muted">Error loading owners: '+escapeHtml(d.owners.error)+'</div>'; else out+='<div class="muted">No owners</div>'; out+='</div>'; out+='<div style="margin-top:12px"><details><summary>Show raw application JSON</summary><pre>'+escapeHtml(JSON.stringify(a, null, 2))+'</pre></details></div>'; out+='</div>'; document.getElementById('detail').innerHTML=out; }).catch(e=>document.getElementById('detail').innerHTML='<div class="section"><strong>Error:</strong>'+escapeHtml(e)+'</div>'); }
function showSP(id){ fetch('/api/section/servicePrincipals/item/' + encodeURIComponent(id)).then(r=>r.json()).then(j=>{ const sp=j.details.servicePrincipal||{}; let out='<div class="section"><h3>'+ escapeHtml(sp.displayName||'Service Principal') +'</h3>'; out+='<div class="muted">id: '+escapeHtml(sp.id||'')+' | appId: '+escapeHtml(sp.appId||'')+'</div>'; out+='<div style="margin-top:12px"><details><summary>Show raw SP JSON</summary><pre>'+escapeHtml(JSON.stringify(sp,null,2))+'</pre></details></div></div>'; document.getElementById('detail').innerHTML=out; }).catch(e=>document.getElementById('detail').innerHTML='<div class="section"><strong>Error:</strong>'+escapeHtml(e)+'</div>'); }
function showDevice(id){ fetch('/api/section/devices/item/' + encodeURIComponent(id)).then(r=>r.json()).then(j=>{ const d=j.details.device||{}; let out='<div class="section"><h3>'+ escapeHtml(d.displayName||d.deviceId||'Device') +'</h3>'; out+='<div class="muted">id: '+escapeHtml(d.id||'')+' | deviceId: '+escapeHtml(d.deviceId||'')+'</div>'; if(Array.isArray(j.details.owners) && j.details.owners.length){ out+='<div style="margin-top:8px"><strong>Owners</strong><ul>'; j.details.owners.forEach(o=>{ const name=o.displayName||o.userPrincipalName||o.mail||o.id; out+='<li><strong>'+escapeHtml(name)+'</strong></li>'; }); out+='</ul></div>'; } out+='<div style="margin-top:12px"><details><summary>Show raw device JSON</summary><pre>'+escapeHtml(JSON.stringify(d,null,2))+'</pre></details></div></div>'; document.getElementById('detail').innerHTML=out; }).catch(e=>document.getElementById('detail').innerHTML='<div class="section"><strong>Error:</strong>'+escapeHtml(e)+'</div>'); }
function showAU(id){ fetch('/api/section/administrativeUnits/item/' + encodeURIComponent(id)).then(r=>r.json()).then(j=>{ const au=j.details.administrativeUnit||{}; let out='<div class="section"><h3>'+ escapeHtml(au.displayName||'Administrative Unit') +'</h3>'; out+='<div class="muted">id: '+escapeHtml(au.id||'')+'</div>'; if(Array.isArray(j.details.members) && j.details.members.length){ out+='<div style="margin-top:8px"><strong>Members ('+j.details.members.length+')</strong><ul>'; j.details.members.forEach(m=>{ const name=m.displayName||m.userPrincipalName||m.id; out+='<li><strong>'+escapeHtml(name)+'</strong></li>'; }); out+='</ul></div>'; } out+='<div style="margin-top:12px"><details><summary>Show raw AU JSON</summary><pre>'+escapeHtml(JSON.stringify(au,null,2))+'</pre></details></div></div>'; document.getElementById('detail').innerHTML=out; }).catch(e=>document.getElementById('detail').innerHTML='<div class="section"><strong>Error:</strong>'+escapeHtml(e)+'</div>'); }

document.getElementById('llmBtn').addEventListener('click', async ()=>{
  const q = document.getElementById('llmQuery').value.trim();
  const redact = document.getElementById('redactToggle').checked;
  const refresh = document.getElementById('refreshToggle').checked;
  const debug = document.getElementById('debugToggle').checked;
  const model = document.getElementById('modelSelect').value;
  if(!q) return alert('Please type a question');
  document.getElementById('llmResp').innerHTML = '<div class="muted">Thinking...</div>';
  try{
    const r = await fetch('/api/local_query', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({q:q, top_k:8, refresh:refresh, redact:redact, debug: debug, model: model})});
    const j = await r.json();
    if(!r.ok){
      document.getElementById('llmResp').innerHTML = '<div class="section"><strong>Error:</strong> '+escapeHtml(JSON.stringify(j))+'</div>';
      return;
    }
    if(j.section && j.items){
      let html = '<div class="section"><h3>List: '+escapeHtml(j.section)+' ('+escapeHtml(String(j.count))+')</h3><pre>'+escapeHtml(JSON.stringify(j.items, null, 2))+'</pre></div>';
      document.getElementById('llmResp').innerHTML = html;
      return;
    }
    if(j.ok){
      document.getElementById('llmResp').innerHTML = '<div class="section"><pre style="white-space:pre-wrap">'+escapeHtml(j.response)+'</pre></div><div class="muted">Context: '+escapeHtml((j.context||[]).map(c=>c.section+':'+(c.displayName||c.id)).join(', '))+'</div>';
      if(debug && j.debug_context){
        document.getElementById('llmResp').innerHTML += '<details style="margin-top:8px"><summary>Debug (prompt & context)</summary><pre>'+escapeHtml(JSON.stringify(j.debug_context, null, 2))+'\\n\\nPROMPT:\\n'+escapeHtml(j.prompt||'')+'</pre></details>';
      }
      if(j.context && j.context.length){
        document.getElementById('contextQuick').textContent = 'Context: ' + j.context.map(c=>c.section+':'+(c.displayName||c.id)).slice(0,6).join(', ');
      }
    } else {
      document.getElementById('llmResp').innerHTML = '<div class="section"><strong>Model error:</strong> '+escapeHtml(j.error||JSON.stringify(j))+'</div>';
      if(debug && j.prompt){
        document.getElementById('llmResp').innerHTML += '<pre>'+escapeHtml(j.prompt)+'</pre>';
      }
    }
  }catch(e){
    document.getElementById('llmResp').innerHTML = '<div class="section"><strong>Error:</strong> '+escapeHtml(String(e))+'</div>';
  }
});

</script>
</body>
</html>
"""

# -------------------------
# CLI / Serve
# -------------------------
def main():
    p = argparse.ArgumentParser(prog="graphhunter", description="GraphHunter - final (cleaned)")
    p.add_argument("--token", help="Graph API Bearer token (optional). If not provided you'll be prompted.")
    p.add_argument("--serve", action="store_true", help="Start local web UI (opens browser).")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", default=5000, type=int)
    p.add_argument("--no-open", action="store_true")
    p.add_argument("--ai", help="One-shot AI query (CLI).")
    p.add_argument("--model", default=DEFAULT_OLLAMA_MODEL)
    p.add_argument("--top-k", type=int, default=8)
    p.add_argument("--refresh", action="store_true")
    p.add_argument("--redact", action="store_true")
    args = p.parse_args()

    token = args.token or os.environ.get("GRAPHHUNTER_TOKEN")
    if not token:
        try:
            token = input("Enter Graph API Bearer token: ").strip()
        except KeyboardInterrupt:
            print("No token provided. Exiting."); sys.exit(1)
    if not token:
        print("Token required. Exiting."); sys.exit(1)

    headers_test = {"Authorization": "Bearer {}".format(token), "Accept": "application/json"}
    try:
        tst = requests.get("{}/me".format(API_BASE), headers=headers_test, timeout=8)
        if tst.status_code in (401,403):
            print("Warning: token returned", tst.status_code, "- it may be invalid or lack scopes. You can continue, but calls may fail.")
    except Exception:
        print("Warning: could not reach Graph to validate token (network). Proceeding; UI will show errors if requests fail.")

    if args.serve:
        print("Starting GraphHunter web UI at http://{}:{}/".format(args.host, args.port))
        try:
            print("[prefetch] fetching sections...")
            prefetch_all_sections(headers_test)
            save_all_sections_to_disk(headers_test, force_refresh=False)
        except Exception as e:
            print("[prefetch] warning:", e)
        app = create_app(token, host=args.host, port=args.port)
        if not args.no_open:
            try: webbrowser.open("http://{}:{}/".format(args.host, args.port))
            except Exception:
                pass
        app.run(host=args.host, port=args.port, debug=False, use_reloader=False)
    else:
        for s in SECTION_FETCHERS.keys():
            try:
                res = get_section_cached(s, headers_test, force_refresh=args.refresh)
                fname = DATA_DIR / f"{s}.json"
                with open(fname, "w", encoding="utf-8") as f:
                    json.dump(res["data"], f, indent=2, ensure_ascii=False)
                print("Saved {} ({} items)".format(fname, len(res["data"])))
            except Exception as e:
                print("[{}] error: {}".format(s, e))

        try:
            save_all_sections_to_disk(headers_test, force_refresh=args.refresh)
            print("Saved combined data/all_data.json")
        except Exception:
            pass

        if args.ai:
            try:
                save_all_sections_to_disk(headers_test, force_refresh=args.refresh)
            except Exception:
                pass
            ctx, _ = retrieve_context(args.ai, top_k=args.top_k, headers=headers_test)
            enriched = []
            for sec, rec in ctx:
                if sec == "directoryRoles" and rec.get("id"):
                    try:
                        det = fetch_role_detail(rec.get("id"), headers_test)
                        rec = rec.copy()
                        rec["members"] = det.get("members", [])
                    except Exception:
                        pass
                if sec == "applications" and rec.get("id"):
                    try:
                        det = fetch_application_detail(rec.get("id"), headers_test)
                        rec = rec.copy()
                        rec["owners"] = det.get("owners", [])
                    except Exception:
                        pass
                enriched.append((sec, rec))
            prompt = build_prompt_from_context(args.ai, enriched, redact=args.redact)
            ok, out = call_local_ollama(prompt, model=args.model)
            if ok:
                print("=== MODEL RESPONSE ===\n")
                print(out)
            else:
                print("MODEL ERROR:\n", out)

if __name__ == "__main__":
    main()

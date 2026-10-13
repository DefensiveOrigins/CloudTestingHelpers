#!/usr/bin/env python3
"""
sa-exposure-check.py
=====================

Empirically validates public exposure of Azure Storage containers/blobs
in one or more subscriptions. Combines authenticated Azure CLI queries
with unauthenticated HTTP(S) requests to confirm what an internet user
could actually access.

Requirements
------------
  az CLI installed and logged in (device code login supported)
  pip install requests

Usage
-----
  python3 sa-exposure-check.py --subscription <id-or-name>
  python3 sa-exposure-check.py --all-subscriptions

Outputs
-------
  <output-dir>/sa_assessment_<timestamp>.csv
  <output-dir>/sa_assessment_summary_<timestamp>.csv

"""

import argparse
import csv
import json
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote
import xml.etree.ElementTree as ET

try:
    import requests
except ImportError:
    sys.exit("ERROR: requests is required. Install with: pip install requests")

SCRIPT_VERSION = "1.0"
USER_AGENT = f"SA-Exposure-Check/{SCRIPT_VERSION} (Authorized Security Assessment)"

FIELDNAMES = [
    "timestamp_utc",
    "subscription_id",
    "storage_account",
    "resource_group",
    "service_type",
    "container_name",
    "auth_can_list_containers_api",
    "container_public_access_setting_api",
    "index_publicly_listable_anonymous",
    "index_check_raw_result",
    "tested_blob",
    "tested_blob_size_bytes",
    "tested_blob_source",
    "tested_blob_url_https",
    "tested_blob_url_http",
    "file_public_no_auth_https",
    "file_https_check_raw_result",
    "file_public_http_unencrypted",
    "file_http_check_raw_result",
    "risk_level",
    "notes",
]

SUMMARY_ROWS = []
_csv_lock = threading.Lock()
VERBOSE = False


def run_az(cmd_args):
    """Run az CLI command and return (returncode, stdout, stderr)."""
    cmd = ["az"] + cmd_args
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, text=True)
        if VERBOSE:
            print(f"[az] {' '.join(cmd_args)} -> rc={p.returncode}")
            if p.stdout:
                print(f"[az stdout] {p.stdout.strip()}")
            if p.stderr:
                print(f"[az stderr] {p.stderr.strip()}")
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        sys.exit("ERROR: az CLI not found. Install Azure CLI and login with 'az login'.")


def ensure_az_login():
    rc, out, err = run_az(["account", "show"])
    if rc != 0:
        print("Azure CLI not logged in. Launching device-code login...\n")
        rc2, o2, e2 = run_az(["login", "--use-device-code"])
        if rc2 != 0:
            sys.exit("ERROR: 'az login' failed. Aborting.")
        # re-check
        rc, out, err = run_az(["account", "show"])
        if rc != 0:
            sys.exit("ERROR: unable to confirm az login after 'az login'.")


def get_subscriptions(all_subs=False, subs_list=None):
    if all_subs:
        rc, out, err = run_az(["account", "list", "-o", "json"])
        if rc != 0:
            sys.exit(f"ERROR: failed to list subscriptions: {err}")
        try:
            arr = json.loads(out)
        except Exception as e:
            sys.exit(f"ERROR: parsing az account list JSON: {e}")
        return [s.get("id") for s in arr]
    return subs_list or []


def list_storage_accounts_for_subscription(subscription_id):
    # set subscription context
    rc, out, err = run_az(["account", "set", "--subscription", subscription_id])
    if rc != 0:
        return []
    rc, out, err = run_az(["storage", "account", "list", "-o", "json"])
    if rc != 0:
        return []
    try:
        arr = json.loads(out)
        if VERBOSE:
            names = [a.get('name') for a in arr]
            print(f"  Found {len(arr)} storage account(s): {', '.join(names)}")
        return arr
    except Exception:
        return []


def parse_container_list_xml(xml_text):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []
    blobs = []
    for c in root.findall("Blobs/Blob"):
        name_el = c.find("Name")
        size_el = c.find("Properties/Content-Length")
        if name_el is None or name_el.text is None:
            continue
        name = name_el.text
        try:
            size = int(size_el.text) if size_el is not None and size_el.text else 0
        except ValueError:
            size = 0
        blobs.append((name, size))
    return blobs


def choose_small_random_object(candidates):
    if not candidates:
        return None, None
    nonzero = [c for c in candidates if c[1] > 0]
    ordered = sorted(nonzero or candidates, key=lambda kv: kv[1])
    pool = ordered[: min(10, len(ordered))]
    import random
    return random.choice(pool)


def anonymous_get(url, timeout, allow_redirects=True):
    headers = {"User-Agent": USER_AGENT}
    try:
        resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=allow_redirects)
        if VERBOSE:
            print(f"[http] GET {url} -> {resp.status_code}")
        return resp, None
    except Exception as e:
        if VERBOSE:
            print(f"[http] GET {url} -> ERROR: {e}")
        return None, str(e)


def test_container_listing(account_name, container_name, timeout):
    # container listing URL
    url = f"https://{account_name}.blob.core.windows.net/{container_name}?restype=container&comp=list"
    if VERBOSE:
        print(f"  [probe] container listing URL: {url}")
    resp, err = anonymous_get(url, timeout)
    if err:
        return None, None, f"Anonymous index check error: {err}"
    if resp.status_code == 200 and "<Blobs>" in resp.text:
        if VERBOSE:
            print(f"  [probe] container listing returned 200 and XML for {account_name}/{container_name}")
        return True, resp.text, None
    if resp.status_code in (403, 401):
        return False, None, None
    if resp.status_code == 404:
        return False, None, "Index check returned 404"
    return None, None, f"Index check returned HTTP {resp.status_code}: {(resp.text or '')[:300]}"


def test_blob_access(account_name, container_name, blob_name, timeout):
    enc = quote(blob_name, safe='')
    host = f"{account_name}.blob.core.windows.net"
    https_url = f"https://{host}/{container_name}/{enc}"
    http_url = f"http://{host}/{container_name}/{enc}"

    # HTTPS
    resp_h, err_h = anonymous_get(https_url, timeout)
    https_public = None
    https_raw = None
    if err_h:
        https_raw = f"HTTPS error: {err_h}"
    else:
        https_raw = f"{resp_h.status_code}"
        if VERBOSE:
            snippet = (resp_h.text or '')[:200]
            print(f"  [probe] HTTPS GET {https_url} -> {resp_h.status_code}; snippet: {snippet}")
        if resp_h.status_code == 200:
            https_public = True
        elif resp_h.status_code in (403, 401):
            https_public = False
        else:
            https_public = None

    # HTTP (unencrypted)
    resp_u, err_u = anonymous_get(http_url, timeout, allow_redirects=False)
    http_public = None
    http_raw = None
    if err_u:
        http_raw = f"HTTP error: {err_u}"
        if VERBOSE:
            print(f"  [probe] HTTP GET {http_url} -> ERROR: {err_u}")
    else:
        http_raw = f"{resp_u.status_code}"
        if VERBOSE:
            print(f"  [probe] HTTP GET {http_url} -> {resp_u.status_code}")
        if resp_u.status_code == 200:
            http_public = True
        elif resp_u.status_code in (301, 302):
            # redirect likely to https
            http_public = False
        elif resp_u.status_code in (403, 401):
            http_public = False
        else:
            http_public = None

    size = None
    source = None
    if resp_h is not None and resp_h.status_code == 200:
        size = len(resp_h.content)
        source = "anonymous_https"
    return https_public, https_raw, http_public, http_raw, size, source, https_url, http_url


def assess_container(subscription_id, account, timeout):
    account_name = account.get("name")
    rg = account.get("resourceGroup")
    if VERBOSE:
        print(f"Assessing storage account: {account_name} (rg={rg})")
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Try authenticated container list (may fail due to RBAC)
    auth_can_list = False
    auth_containers = None
    rc, out, err = run_az(["storage", "container", "list", "--account-name", account_name, "--auth-mode", "login", "-o", "json"])
    if rc == 0:
        try:
            auth_containers = json.loads(out)
            auth_can_list = True
        except Exception:
            auth_containers = None

    rows = []
    containers = []
    if auth_containers is not None:
        containers = [c.get("name") for c in auth_containers]
    else:
        # If we cannot list containers, attempt to probe a few common container names
        containers = ["$web"]

    for container in containers:
        row = {fn: "" for fn in FIELDNAMES}
        row.update({
            "timestamp_utc": timestamp,
            "subscription_id": subscription_id,
            "storage_account": account_name,
            "resource_group": rg,
            "container_name": container,
            "auth_can_list_containers_api": auth_can_list,
        })

        # If we had authenticated container metadata, pick up public access setting
        if auth_can_list and auth_containers is not None:
            try:
                cmeta = next((c for c in auth_containers if c.get("name") == container), {})
                pub = cmeta.get("properties", {}).get("publicAccess") or cmeta.get("publicAccess")
                row["container_public_access_setting_api"] = pub
            except Exception:
                row["container_public_access_setting_api"] = "(error)"

        # Anonymous container listing check
        idx_public, idx_xml, idx_note = test_container_listing(account_name, container, timeout)
        row["index_publicly_listable_anonymous"] = idx_public
        row["index_check_raw_result"] = idx_note if idx_note else ("200" if idx_public else "403/401/other")

        blobs = []
        tested_blob = None
        tested_blob_size = None
        tested_blob_source = None

        # If we have authenticated blob list for this container, use it to select blob
        if auth_can_list:
            rc2, out2, err2 = run_az(["storage", "blob", "list", "--container-name", container, "--account-name", account_name, "--auth-mode", "login", "-o", "json"])
            if rc2 == 0:
                try:
                    blobs_json = json.loads(out2)
                    blobs = [(b.get("name"), int(b.get("properties", {}).get("contentLength") or 0)) for b in blobs_json]
                except Exception:
                    blobs = []

        # If anonymous index returned XML, parse for blobs
        if idx_xml:
            blobs = parse_container_list_xml(idx_xml) or blobs

        if blobs:
            tested_blob, tested_blob_size = choose_small_random_object(blobs)
            tested_blob_source = "authenticated_list" if auth_can_list and not idx_xml else "anonymous_index" if idx_xml else "authenticated_list"

        if tested_blob:
            (https_public, https_raw, http_public, http_raw, size, source, https_url, http_url) = test_blob_access(account_name, container, tested_blob, timeout)
            row.update({
                "tested_blob": tested_blob,
                "tested_blob_size_bytes": size or tested_blob_size or "",
                "tested_blob_source": tested_blob_source,
                "tested_blob_url_https": https_url,
                "tested_blob_url_http": http_url,
                "file_public_no_auth_https": https_public,
                "file_https_check_raw_result": https_raw,
                "file_public_http_unencrypted": http_public,
                "file_http_check_raw_result": http_raw,
            })
        else:
            row.update({
                "tested_blob": "(none found)",
                "tested_blob_size_bytes": "",
                "tested_blob_source": "",
            })

        # Determine risk level
        if row.get("file_public_no_auth_https") is True:
            risk = "CRITICAL: public blob accessible (HTTPS)"
        elif row.get("file_public_http_unencrypted") is True:
            risk = "HIGH: blob accessible over unencrypted HTTP"
        elif row.get("index_publicly_listable_anonymous") is True:
            risk = "HIGH: container listing publicly available"
        elif row.get("file_public_no_auth_https") is False and row.get("index_publicly_listable_anonymous") is False:
            risk = "OK: no public access detected"
        else:
            risk = "UNKNOWN: unable to verify"
        row["risk_level"] = risk

        # Notes
        notes = []
        if not auth_can_list:
            notes.append("Authenticated container list failed or denied")
        if idx_note:
            notes.append(str(idx_note))
        row["notes"] = "; ".join(notes)

        rows.append(row)

        with _csv_lock:
            SUMMARY_ROWS.append({
                "subscription_id": subscription_id,
                "storage_account": account_name,
                "container_name": container,
                "index_publicly_listable_anonymous": row.get("index_publicly_listable_anonymous"),
                "file_public_no_auth_https": row.get("file_public_no_auth_https"),
                "file_public_http_unencrypted": row.get("file_public_http_unencrypted"),
                "risk_level": row.get("risk_level"),
            })

    return rows


def assess_fileshares(subscription_id, account, timeout):
    account_name = account.get("name")
    rg = account.get("resourceGroup")
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    rows = []

    # Try authenticated share list
    shares = []
    rc, out, err = run_az(["storage", "share", "list", "--account-name", account_name, "--auth-mode", "login", "-o", "json"])
    if rc == 0:
        try:
            j = json.loads(out)
            shares = [s.get("name") for s in j]
        except Exception:
            shares = []
    else:
        shares = ["$root"]

    for share in shares:
        row = {fn: "" for fn in FIELDNAMES}
        row.update({
            "timestamp_utc": timestamp,
            "subscription_id": subscription_id,
            "storage_account": account_name,
            "resource_group": rg,
            "service_type": "files",
            "container_name": share,
        })

        # Anonymous share listing
        url = f"https://{account_name}.file.core.windows.net/{share}?restype=share&comp=list"
        if VERBOSE:
            print(f"  [probe] file share listing URL: {url}")
        resp, err = anonymous_get(url, timeout)
        if err:
            row["index_publicly_listable_anonymous"] = None
            row["index_check_raw_result"] = f"error: {err}"
        else:
            if resp.status_code == 200 and "<Entries>" in resp.text:
                row["index_publicly_listable_anonymous"] = True
                row["index_check_raw_result"] = "200"
            elif resp.status_code in (403, 401):
                row["index_publicly_listable_anonymous"] = False
                row["index_check_raw_result"] = f"{resp.status_code}"
            else:
                row["index_publicly_listable_anonymous"] = None
                row["index_check_raw_result"] = f"{resp.status_code}"

        # Pick a sample file if possible via authenticated list
        tested_blob = None
        tested_blob_size = None
        if rc == 0:
            # try listing root directory files
            rc2, out2, err2 = run_az(["storage", "file", "list", "--share-name", share, "--account-name", account_name, "--auth-mode", "login", "-o", "json"])
            if rc2 == 0:
                try:
                    j2 = json.loads(out2)
                    files = [(f.get("name"), int(f.get("properties", {}).get("contentLength") or 0)) for f in j2]
                except Exception:
                    files = []
                if files:
                    tested_blob, tested_blob_size = choose_small_random_object(files)

        if tested_blob:
            https_url = f"https://{account_name}.file.core.windows.net/{share}/{quote(tested_blob, safe='')}"
            http_url = https_url.replace("https://", "http://")
            resp_h, err_h = anonymous_get(https_url, timeout)
            if err_h:
                row["file_https_check_raw_result"] = f"error: {err_h}"
                row["file_public_no_auth_https"] = None
            else:
                row["file_https_check_raw_result"] = str(resp_h.status_code)
                row["file_public_no_auth_https"] = resp_h.status_code == 200

            resp_u, err_u = anonymous_get(http_url, timeout, allow_redirects=False)
            if err_u:
                row["file_http_check_raw_result"] = f"error: {err_u}"
                row["file_public_http_unencrypted"] = None
            else:
                row["file_http_check_raw_result"] = str(resp_u.status_code)
                row["file_public_http_unencrypted"] = resp_u.status_code == 200

            row.update({
                "tested_blob": tested_blob,
                "tested_blob_size_bytes": tested_blob_size or "",
                "tested_blob_source": "authenticated_list",
                "tested_blob_url_https": https_url,
                "tested_blob_url_http": http_url,
            })
        else:
            row.update({"tested_blob": "(none found)", "tested_blob_size_bytes": "", "tested_blob_source": ""})

        # Risk
        if row.get("file_public_no_auth_https") is True:
            row["risk_level"] = "CRITICAL: public file accessible (HTTPS)"
        elif row.get("file_public_http_unencrypted") is True:
            row["risk_level"] = "HIGH: file accessible over unencrypted HTTP"
        elif row.get("index_publicly_listable_anonymous") is True:
            row["risk_level"] = "HIGH: file share listing publicly available"
        else:
            row["risk_level"] = "UNKNOWN: unable to verify" if row.get("index_publicly_listable_anonymous") is None else "OK: no public access detected"

        rows.append(row)
        with _csv_lock:
            SUMMARY_ROWS.append({
                "subscription_id": subscription_id,
                "storage_account": account_name,
                "container_name": share,
                "index_publicly_listable_anonymous": row.get("index_publicly_listable_anonymous"),
                "file_public_no_auth_https": row.get("file_public_no_auth_https"),
                "file_public_http_unencrypted": row.get("file_public_http_unencrypted"),
                "risk_level": row.get("risk_level"),
            })

    return rows


def assess_queues(subscription_id, account, timeout):
    account_name = account.get("name")
    rg = account.get("resourceGroup")
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    rows = []

    # Authenticated queue list
    rc, out, err = run_az(["storage", "queue", "list", "--account-name", account_name, "--auth-mode", "login", "-o", "json"])
    queues = []
    if rc == 0:
        try:
            j = json.loads(out)
            queues = [q.get("name") for q in j]
        except Exception:
            queues = []

    for qname in (queues or []):
        row = {fn: "" for fn in FIELDNAMES}
        row.update({
            "timestamp_utc": timestamp,
            "subscription_id": subscription_id,
            "storage_account": account_name,
            "resource_group": rg,
            "service_type": "queues",
            "container_name": qname,
        })

        # anonymous metadata check
        url = f"https://{account_name}.queue.core.windows.net/{qname}?comp=metadata"
        resp, err = anonymous_get(url, timeout)
        if err:
            row["index_publicly_listable_anonymous"] = None
            row["index_check_raw_result"] = f"error: {err}"
        else:
            row["index_publicly_listable_anonymous"] = resp.status_code == 200
            row["index_check_raw_result"] = str(resp.status_code)

        # try messages peek
        msg_url = f"https://{account_name}.queue.core.windows.net/{qname}/messages?numofmessages=1"
        r2, e2 = anonymous_get(msg_url, timeout)
        if e2:
            row["file_https_check_raw_result"] = f"error: {e2}"
            row["file_public_no_auth_https"] = None
        else:
            row["file_https_check_raw_result"] = str(r2.status_code)
            row["file_public_no_auth_https"] = r2.status_code == 200

        # risk
        if row.get("file_public_no_auth_https") is True:
            row["risk_level"] = "CRITICAL: queue messages retrievable anonymously"
        elif row.get("index_publicly_listable_anonymous") is True:
            row["risk_level"] = "HIGH: queue metadata accessible"
        else:
            row["risk_level"] = "OK: no public access detected" if row.get("index_publicly_listable_anonymous") is False else "UNKNOWN: unable to verify"

        rows.append(row)
        with _csv_lock:
            SUMMARY_ROWS.append({
                "subscription_id": subscription_id,
                "storage_account": account_name,
                "container_name": qname,
                "index_publicly_listable_anonymous": row.get("index_publicly_listable_anonymous"),
                "file_public_no_auth_https": row.get("file_public_no_auth_https"),
                "file_public_http_unencrypted": row.get("file_public_http_unencrypted"),
                "risk_level": row.get("risk_level"),
            })

    return rows


def assess_tables(subscription_id, account, timeout):
    account_name = account.get("name")
    rg = account.get("resourceGroup")
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    rows = []

    # Authenticated table list
    rc, out, err = run_az(["storage", "table", "list", "--account-name", account_name, "--auth-mode", "login", "-o", "json"])
    tables = []
    if rc == 0:
        try:
            j = json.loads(out)
            tables = [t.get("name") for t in j]
        except Exception:
            tables = []

    # anonymous Tables endpoint
    url = f"https://{account_name}.table.core.windows.net/Tables"
    resp, err = anonymous_get(url, timeout)
    list_public = None
    if err:
        list_public = None
    else:
        list_public = resp.status_code == 200

    if tables:
        for t in tables:
            row = {fn: "" for fn in FIELDNAMES}
            row.update({
                "timestamp_utc": timestamp,
                "subscription_id": subscription_id,
                "storage_account": account_name,
                "resource_group": rg,
                "service_type": "tables",
                "container_name": t,
                "index_publicly_listable_anonymous": list_public,
                "index_check_raw_result": str(resp.status_code) if resp is not None else "",
            })
            # test table entity read
            tab_url = f"https://{account_name}.table.core.windows.net/{t}"
            r2, e2 = anonymous_get(tab_url, timeout)
            row["file_https_check_raw_result"] = str(r2.status_code) if r2 is not None else f"error: {e2}"
            row["file_public_no_auth_https"] = (r2 is not None and r2.status_code == 200)
            row["risk_level"] = "CRITICAL: table data accessible" if row["file_public_no_auth_https"] else ("HIGH: tables list available" if list_public else "UNKNOWN")
            rows.append(row)
            with _csv_lock:
                SUMMARY_ROWS.append({
                    "subscription_id": subscription_id,
                    "storage_account": account_name,
                    "container_name": t,
                    "index_publicly_listable_anonymous": row.get("index_publicly_listable_anonymous"),
                    "file_public_no_auth_https": row.get("file_public_no_auth_https"),
                    "file_public_http_unencrypted": row.get("file_public_http_unencrypted"),
                    "risk_level": row.get("risk_level"),
                })
    else:
        # if no authenticated table list, still record the service-level check
        row = {fn: "" for fn in FIELDNAMES}
        row.update({
            "timestamp_utc": timestamp,
            "subscription_id": subscription_id,
            "storage_account": account_name,
            "resource_group": rg,
            "service_type": "tables",
            "container_name": "(none listed)",
            "index_publicly_listable_anonymous": list_public,
            "index_check_raw_result": str(resp.status_code) if resp is not None else "",
            "risk_level": "UNKNOWN",
        })
        rows.append(row)

    return rows


def assess_adls(subscription_id, account, timeout):
    # ADLS Gen2: probe filesystem (container) listing on dfs and blob endpoints
    account_name = account.get("name")
    rg = account.get("resourceGroup")
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    rows = []

    # try to list filesystems via az (if CLi supports it)
    rc, out, err = run_az(["storage", "fs", "list", "--account-name", account_name, "--auth-mode", "login", "-o", "json"]) 
    filesystems = []
    if rc == 0:
        try:
            j = json.loads(out)
            filesystems = [f.get("name") for f in j]
        except Exception:
            filesystems = []

    # fallback to blob containers if fs list not available
    if not filesystems:
        rc2, out2, err2 = run_az(["storage", "container", "list", "--account-name", account_name, "--auth-mode", "login", "-o", "json"])
        if rc2 == 0:
            try:
                j2 = json.loads(out2)
                filesystems = [c.get("name") for c in j2]
            except Exception:
                filesystems = []

    for fs in (filesystems or []):
        row = {fn: "" for fn in FIELDNAMES}
        row.update({
            "timestamp_utc": timestamp,
            "subscription_id": subscription_id,
            "storage_account": account_name,
            "resource_group": rg,
            "service_type": "adls",
            "container_name": fs,
        })

        # Try dfs listing
        dfs_url = f"https://{account_name}.dfs.core.windows.net/{fs}?resource=filesystem&recursive=false"
        resp, err = anonymous_get(dfs_url, timeout)
        if err:
            row["index_publicly_listable_anonymous"] = None
            row["index_check_raw_result"] = f"error: {err}"
        else:
            row["index_publicly_listable_anonymous"] = resp.status_code == 200
            row["index_check_raw_result"] = str(resp.status_code)

        # also try blob endpoint listing
        blob_url = f"https://{account_name}.blob.core.windows.net/{fs}?restype=container&comp=list"
        r2, e2 = anonymous_get(blob_url, timeout)
        if r2 is not None and r2.status_code == 200:
            row["index_publicly_listable_anonymous"] = True

        # pick sample via authenticated listing if possible
        tested_blob = None
        tested_blob_size = None
        if rc == 0:
            # fs listing via az already retrieved items
            # try to list items via az storage fs file list
            rc3, out3, err3 = run_az(["storage", "fs", "file", "list", "--file-system", fs, "--account-name", account_name, "--auth-mode", "login", "-o", "json"]) 
            if rc3 == 0:
                try:
                    j3 = json.loads(out3)
                    items = [(it.get("name"), int(it.get("contentLength") or 0)) for it in j3]
                except Exception:
                    items = []
                if items:
                    tested_blob, tested_blob_size = choose_small_random_object(items)

        if tested_blob:
            https_url = f"https://{account_name}.dfs.core.windows.net/{fs}/{quote(tested_blob, safe='')}"
            r3, e3 = anonymous_get(https_url, timeout)
            row["file_https_check_raw_result"] = str(r3.status_code) if r3 is not None else f"error: {e3}"
            row["file_public_no_auth_https"] = (r3 is not None and r3.status_code == 200)
            row.update({
                "tested_blob": tested_blob,
                "tested_blob_size_bytes": tested_blob_size or "",
                "tested_blob_source": "authenticated_list",
                "tested_blob_url_https": https_url,
                "tested_blob_url_http": https_url.replace("https://","http://"),
            })

        # risk
        if row.get("file_public_no_auth_https") is True:
            row["risk_level"] = "CRITICAL: ADLS item accessible (HTTPS)"
        elif row.get("index_publicly_listable_anonymous") is True:
            row["risk_level"] = "HIGH: ADLS filesystem listing accessible"
        else:
            row["risk_level"] = "UNKNOWN: unable to verify" if row.get("index_publicly_listable_anonymous") is None else "OK: no public access detected"

        rows.append(row)
        with _csv_lock:
            SUMMARY_ROWS.append({
                "subscription_id": subscription_id,
                "storage_account": account_name,
                "container_name": fs,
                "index_publicly_listable_anonymous": row.get("index_publicly_listable_anonymous"),
                "file_public_no_auth_https": row.get("file_public_no_auth_https"),
                "file_public_http_unencrypted": row.get("file_public_http_unencrypted"),
                "risk_level": row.get("risk_level"),
            })

    return rows


def write_csv(rows, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)


def build_account_summary():
    accounts = {}
    order = []
    for r in SUMMARY_ROWS:
        acct = r.get("subscription_id") or "Unknown"
        if acct not in accounts:
            accounts[acct] = {
                "subscription_id": acct,
                "total_containers": 0,
                "containers_with_public_index": 0,
                "containers_with_public_blob": 0,
                "containers_with_unencrypted_http": 0,
            }
            order.append(acct)
        entry = accounts[acct]
        entry["total_containers"] += 1
        if r.get("index_publicly_listable_anonymous") is True:
            entry["containers_with_public_index"] += 1
        if r.get("file_public_no_auth_https") is True:
            entry["containers_with_public_blob"] += 1
        if r.get("file_public_http_unencrypted") is True:
            entry["containers_with_unencrypted_http"] += 1

    rows = []
    for acct in order:
        rows.append(accounts[acct])
    return rows


def parse_args():
    parser = argparse.ArgumentParser(description="Validate Azure Storage public exposure (containers and blobs)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--subscription", nargs='+', help="One or more subscription ids or names to assess")
    group.add_argument("--all-subscriptions", action='store_true', help="Assess every subscription available to the logged-in user")
    parser.add_argument("--output-dir", default='.', help="Directory to write CSV files")
    parser.add_argument("--timeout", type=float, default=10.0, help="HTTP request timeout in seconds")
    parser.add_argument("--threads", type=int, default=5, help="Worker threads for container checks per subscription")
    parser.add_argument("-v", "--verbose", action='store_true')
    parser.add_argument("--services", nargs='+', choices=["blobs","files","queues","tables","adls"],
                        help="Which storage services to assess (default: all)")
    return parser.parse_args()


def main():
    args = parse_args()
    global VERBOSE
    VERBOSE = bool(args.verbose)
    outdir = Path(args.output_dir)
    outdir.mkdir(parents=True, exist_ok=True)

    ensure_az_login()

    subs = get_subscriptions(all_subs=args.all_subscriptions, subs_list=args.subscription)
    if not subs:
        sys.exit("No subscriptions to assess.")

    all_rows = []
    # determine services to test
    services = args.services if args.services else ["blobs", "files", "queues", "tables", "adls"]
    for sub in subs:
        print(f"Assessing subscription {sub} ...")
        accounts = list_storage_accounts_for_subscription(sub)
        if not accounts:
            print(f"  No storage accounts found or failed to list for subscription {sub}")
            continue

        # Assess each storage account; containers processed with threadpool inside assess_container
        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            futures = []
            for acct in accounts:
                if "blobs" in services:
                    futures.append(ex.submit(assess_container, sub, acct, args.timeout))
                if "files" in services:
                    futures.append(ex.submit(assess_fileshares, sub, acct, args.timeout))
                if "queues" in services:
                    futures.append(ex.submit(assess_queues, sub, acct, args.timeout))
                if "tables" in services:
                    futures.append(ex.submit(assess_tables, sub, acct, args.timeout))
                if "adls" in services:
                    futures.append(ex.submit(assess_adls, sub, acct, args.timeout))

            for fut in as_completed(futures):
                try:
                    rows = fut.result()
                    if rows:
                        all_rows.extend(rows)
                except Exception as e:
                    print(f"Error assessing account: {e}")

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    csv_path = outdir / f"sa_assessment_{ts}.csv"
    write_csv(all_rows, csv_path)
    summary_rows = build_account_summary()
    summary_path = outdir / f"sa_assessment_summary_{ts}.csv"
    # Write summary CSV
    with open(summary_path, "w", newline="", encoding="utf-8") as f:
        fieldnames = ["subscription_id", "total_containers", "containers_with_public_index", "containers_with_public_blob", "containers_with_unencrypted_http"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in summary_rows:
            writer.writerow(r)

    # Print brief summary
    total = len(SUMMARY_ROWS)
    critical = sum(1 for r in SUMMARY_ROWS if str(r.get("risk_level","")).startswith("CRITICAL"))
    high = sum(1 for r in SUMMARY_ROWS if str(r.get("risk_level","")).startswith("HIGH"))
    unknown = sum(1 for r in SUMMARY_ROWS if str(r.get("risk_level","")).startswith("UNKNOWN"))
    ok = sum(1 for r in SUMMARY_ROWS if str(r.get("risk_level","")).startswith("OK"))

    print(f"\nAssessment complete. Results written to: {csv_path} and {summary_path}")
    print(f"Total containers assessed: {total}")
    print(f"  CRITICAL (public blob accessible): {critical}")
    print(f"  HIGH (unencrypted HTTP or public listing): {high}")
    print(f"  UNKNOWN (unable to verify): {unknown}")
    print(f"  OK (no public access detected): {ok}")


if __name__ == '__main__':
    main()

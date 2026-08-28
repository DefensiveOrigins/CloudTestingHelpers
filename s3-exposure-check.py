#!/usr/bin/env python3
"""
s3_public_exposure_check.py
============================

Purpose
-------
Empirically validates the real-world public exposure of S3 buckets in one or
more AWS accounts/profiles, rather than relying solely on the S3 configuration
APIs (GetPublicAccessBlock, GetBucketPolicyStatus, GetBucketAcl,
GetBucketEncryption) -- which are frequently blocked by IAM policy even under
"read-only" roles.

The script combines two independent data sources:

  1. AUTHENTICATED calls using the caller's own AWS credentials (profile):
       - s3:ListBuckets                (enumerate buckets in the account)
       - s3:GetBucketLocation          (best-effort, informational)
       - s3:ListBucket (ListObjectsV2) (best-effort -- used to select a real,
                                          small object to test with)
       - s3:GetPublicAccessBlock / GetBucketPolicyStatus / GetBucketAcl /
         GetBucketEncryption           (best-effort -- these are the calls
                                          that typically fail with
                                          AccessDenied for the operator's own
                                          role; failures are recorded, not
                                          treated as fatal)

  2. UNAUTHENTICATED (anonymous) HTTP(S) requests, exactly as a random person
     on the internet would issue them:
       - GET on the bucket root (path-style) to see if the bucket INDEX
         (object listing) is publicly viewable without any credentials.
       - GET on one specific object (chosen from whichever listing succeeded)
         over HTTPS with no credentials, to see if the OBJECT itself is
         publicly downloadable.
       - GET on that same object over plain HTTP (no TLS) with no
         credentials, to see if the object can be retrieved over an
         unencrypted channel.

Because the anonymous checks never send AWS credentials, they reflect what
ANY unauthenticated internet user could actually do to the bucket -- which is
the ground truth the assessment cares about, independent of whatever the
operator's own IAM role is or is not allowed to read.

Authorized use only
--------------------
This tool issues unauthenticated HTTP requests to AWS S3 endpoints for the
buckets it discovers. Only run it against accounts/buckets you are
authorized to assess.

Requirements
------------
    pip install boto3 requests alive-progress tabulate

Usage
-----
    python3 s3_public_exposure_check.py --profile prod
    python3 s3_public_exposure_check.py --profile prod dev qa
    python3 s3_public_exposure_check.py --all-profiles
    python3 s3_public_exposure_check.py --all-profiles --output-dir ./results -v

Outputs
-------
    <output-dir>/s3_assessment_<timestamp>.csv   -- machine-readable results
    <output-dir>/s3_assessment_<timestamp>.log   -- detailed run log
    STDOUT                                       -- brief progress + summary table
"""

import argparse
import configparser
import csv
import logging
import random
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlparse
import xml.etree.ElementTree as ET

try:
    import boto3
    import botocore
    from botocore.config import Config as BotoConfig
except ImportError:
    sys.exit("ERROR: boto3 is required. Install with: pip install boto3")

try:
    import requests
except ImportError:
    sys.exit("ERROR: requests is required. Install with: pip install requests")

try:
    from alive_progress import alive_bar
except ImportError:
    sys.exit("ERROR: alive-progress is required. Install with: pip install alive-progress")

try:
    from tabulate import tabulate
    HAVE_TABULATE = True
except ImportError:
    HAVE_TABULATE = False


SCRIPT_VERSION = "1.0"
USER_AGENT = f"BHIS-S3-Public-Exposure-Check/{SCRIPT_VERSION} (Authorized Security Assessment)"
S3_NAMESPACE = {"s3": "http://s3.amazonaws.com/doc/2006-03-01/"}

FIELDNAMES = [
    "timestamp_utc",
    "aws_account_id",
    "profile",
    "bucket_name",
    "region",
    "role_can_list_objects_api",
    "config_api_status",
    "public_access_block",
    "bucket_policy_public",
    "acl_public_grant",
    "encryption_status",
    "index_publicly_listable_anonymous",
    "index_check_raw_result",
    "tested_file",
    "tested_file_size_bytes",
    "tested_file_source",
    "tested_file_url_https",
    "tested_file_url_http",
    "file_public_no_auth_https",
    "file_https_check_raw_result",
    "file_public_http_unencrypted",
    "file_http_check_raw_result",
    "risk_level",
    "notes",
]

# Buckets/results accumulated for the final STDOUT summary table
SUMMARY_ROWS = []

# Global handles so a Ctrl+C can flush/close cleanly
_csv_file_handle = None
_logger = None


# --------------------------------------------------------------------------
# Setup helpers
# --------------------------------------------------------------------------

def build_logger(log_path: Path, verbose: bool) -> logging.Logger:
    logger = logging.getLogger("s3check")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)-7s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    ))

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    console_handler.setFormatter(logging.Formatter("%(message)s"))

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger


def get_profiles_from_credentials_file(cred_path: Path, logger: logging.Logger):
    if not cred_path.exists():
        logger.error(f"Credentials file not found: {cred_path}")
        return []
    parser = configparser.ConfigParser()
    parser.read(cred_path)
    profiles = list(parser.sections())
    logger.info(f"Discovered {len(profiles)} profile(s) in {cred_path}: {', '.join(profiles) or '(none)'}")
    return profiles


def error_code(exc: "botocore.exceptions.ClientError") -> str:
    try:
        return exc.response["Error"]["Code"]
    except Exception:
        return "Unknown"


def is_access_denied(code: str) -> bool:
    return code in ("AccessDenied", "AccessDeniedException", "UnauthorizedAccess")


# --------------------------------------------------------------------------
# Authenticated (API) checks -- expected to fail under a locked-down role;
# failures are recorded, not fatal.
# --------------------------------------------------------------------------

def get_bucket_region(s3_client, bucket_name, logger):
    try:
        resp = s3_client.get_bucket_location(Bucket=bucket_name)
        loc = resp.get("LocationConstraint")
        if not loc:
            return "us-east-1"
        if loc == "EU":
            return "eu-west-1"
        return loc
    except botocore.exceptions.ClientError as e:
        code = error_code(e)
        logger.debug(f"  GetBucketLocation failed ({code}) for {bucket_name}")
        return "Unknown" if not is_access_denied(code) else "AccessDenied"
    except Exception as e:
        logger.debug(f"  GetBucketLocation error for {bucket_name}: {e}")
        return "Unknown"


def check_bucket_configuration(s3_client, bucket_name, logger):
    """Best-effort configuration reads. In the common case (locked-down
    assessment role) these all return AccessDenied -- that is expected and is
    exactly why the anonymous HTTP tests further down exist."""
    result = {
        "public_access_block": "Unknown",
        "bucket_policy_public": "Unknown",
        "acl_public_grant": "Unknown",
        "encryption_status": "Unknown",
    }
    denied_count = 0
    total_checks = 4

    # Public Access Block configuration
    try:
        resp = s3_client.get_public_access_block(Bucket=bucket_name)
        cfg = resp["PublicAccessBlockConfiguration"]
        fully_blocked = all(cfg.get(k, False) for k in
                             ("BlockPublicAcls", "IgnorePublicAcls",
                              "BlockPublicPolicy", "RestrictPublicBuckets"))
        result["public_access_block"] = "FullyBlocked" if fully_blocked else f"Partial:{cfg}"
    except botocore.exceptions.ClientError as e:
        code = error_code(e)
        if code == "NoSuchPublicAccessBlockConfiguration":
            result["public_access_block"] = "NotConfigured"
        elif is_access_denied(code):
            result["public_access_block"] = "AccessDenied"
            denied_count += 1
        else:
            result["public_access_block"] = f"Error:{code}"
        logger.debug(f"  GetPublicAccessBlock[{bucket_name}] -> {code}")

    # Bucket policy public status
    try:
        resp = s3_client.get_bucket_policy_status(Bucket=bucket_name)
        result["bucket_policy_public"] = str(resp["PolicyStatus"]["IsPublic"])
    except botocore.exceptions.ClientError as e:
        code = error_code(e)
        if code == "NoSuchBucketPolicy":
            result["bucket_policy_public"] = "NoPolicy"
        elif is_access_denied(code):
            result["bucket_policy_public"] = "AccessDenied"
            denied_count += 1
        else:
            result["bucket_policy_public"] = f"Error:{code}"
        logger.debug(f"  GetBucketPolicyStatus[{bucket_name}] -> {code}")

    # ACL grants to AllUsers / AuthenticatedUsers
    try:
        resp = s3_client.get_bucket_acl(Bucket=bucket_name)
        public_grant = False
        for grant in resp.get("Grants", []):
            uri = grant.get("Grantee", {}).get("URI", "")
            if uri.endswith("AllUsers") or uri.endswith("AuthenticatedUsers"):
                public_grant = True
        result["acl_public_grant"] = str(public_grant)
    except botocore.exceptions.ClientError as e:
        code = error_code(e)
        if is_access_denied(code):
            result["acl_public_grant"] = "AccessDenied"
            denied_count += 1
        else:
            result["acl_public_grant"] = f"Error:{code}"
        logger.debug(f"  GetBucketAcl[{bucket_name}] -> {code}")

    # Default encryption
    try:
        s3_client.get_bucket_encryption(Bucket=bucket_name)
        result["encryption_status"] = "Enabled"
    except botocore.exceptions.ClientError as e:
        code = error_code(e)
        if code == "ServerSideEncryptionConfigurationNotFoundError":
            result["encryption_status"] = "Disabled"
        elif is_access_denied(code):
            result["encryption_status"] = "AccessDenied"
            denied_count += 1
        else:
            result["encryption_status"] = f"Error:{code}"
        logger.debug(f"  GetBucketEncryption[{bucket_name}] -> {code}")

    if denied_count == 0:
        status = "Accessible"
    elif denied_count == total_checks:
        status = "AccessDenied"
    else:
        status = "Partial"

    return status, result


def list_objects_via_api(s3_client, bucket_name, max_keys, logger):
    """Best-effort: many read-only roles retain s3:ListBucket even when the
    config-reading calls above are denied. Returns (can_list, contents_list)
    where contents_list is a list of (key, size) tuples."""
    try:
        resp = s3_client.list_objects_v2(Bucket=bucket_name, MaxKeys=max_keys)
        contents = [(o["Key"], o.get("Size", 0)) for o in resp.get("Contents", [])]
        logger.debug(f"  ListObjectsV2[{bucket_name}] via API succeeded, {len(contents)} object(s) seen")
        return True, contents
    except botocore.exceptions.ClientError as e:
        code = error_code(e)
        logger.debug(f"  ListObjectsV2[{bucket_name}] via API failed: {code}")
        return False, []
    except Exception as e:
        logger.debug(f"  ListObjectsV2[{bucket_name}] via API error: {e}")
        return False, []


# --------------------------------------------------------------------------
# Anonymous / unauthenticated HTTP checks -- the actual ground-truth tests
# --------------------------------------------------------------------------

def anonymous_get(url, timeout, logger):
    """Wrapper around requests.get with no auth, consistent UA/timeout, and
    uniform exception handling."""
    headers = {"User-Agent": USER_AGENT}
    try:
        resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        return resp, None
    except requests.exceptions.RequestException as e:
        logger.debug(f"  Anonymous GET {url} failed: {e}")
        return None, str(e)


def resolve_host(region):
    """Build the S3 endpoint host to use. Prefer the region-specific
    endpoint when we know the region -- the legacy global 's3.amazonaws.com'
    endpoint does not reliably auto-redirect for buckets in newer "opt-in"
    regions (e.g. ap-east-1, me-south-1, af-south-1, eu-south-1), which
    otherwise shows up as an unexplained 400 on every check for that bucket."""
    if region and region not in ("Unknown", "AccessDenied", "us-east-1", ""):
        return f"s3.{region}.amazonaws.com"
    return "s3.amazonaws.com"


def parse_redirect_hint(text):
    """S3 signals 'wrong endpoint' two different ways, depending on why:
      - HTTP 400 AuthorizationHeaderMalformed: XML body has a <Region> tag.
      - HTTP 301 PermanentRedirect: XML body has an <Endpoint> tag instead
        (this is the common case for any bucket outside us-east-1 hit via
        the flat s3.amazonaws.com endpoint) -- and critically, this 301
        response does NOT include an HTTP Location header, so `requests`
        has nothing to auto-follow and just returns the bare 301.
    Returns ("region", value) or ("endpoint", value) or None."""
    if not text:
        return None
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None
    region_el = root.find("Region")
    if region_el is not None and region_el.text:
        return ("region", region_el.text)
    endpoint_el = root.find("Endpoint")
    if endpoint_el is not None and endpoint_el.text:
        return ("endpoint", endpoint_el.text)
    return None


def host_from_redirect_hint(hint, bucket_name):
    kind, value = hint
    if kind == "region":
        return resolve_host(value)
    # kind == "endpoint": value may be virtual-hosted style
    # ("bucket.s3.eu-west-1.amazonaws.com"); strip the bucket prefix so we
    # keep using path-style requests consistently.
    host = value
    prefix = f"{bucket_name}."
    if host.startswith(prefix):
        host = host[len(prefix):]
    return host


def resolve_working_host(bucket_name, region_hint, timeout, logger, max_hops=3):
    """Determine the S3 endpoint host that actually serves anonymous
    path-style requests for this bucket.

    Two independent signals are used, in priority order, because neither one
    alone is reliable enough:

      1. The `x-amz-bucket-region` RESPONSE HEADER. AWS sets this on almost
         every response for a bucket that exists -- a clean 200, a 403
         (private bucket, still tells you its real region), a 301, or a 400
         -- and it requires no credentials at all. This is the standard
         technique tools use to discover a bucket's true region
         unauthenticated, and it does not depend on the error body having
         any particular shape.
      2. Parsing the XML error body for a <Region> (400
         AuthorizationHeaderMalformed) or <Endpoint> (301 PermanentRedirect)
         tag. Kept as a fallback for the rare case where the header itself
         is stripped or absent, since AWS's exact error body content for a
         301 varies and sometimes omits both of these tags entirely.

    `requests`'s automatic redirect handling isn't relied on here because it
    only fires when an HTTP Location header is present -- S3 frequently
    signals "wrong endpoint" via body/header instead, with no Location.

    Returns (host_used, response_from_bucket_root_or_None, err_or_None). The
    response is reused as the index-listing check so we don't issue a
    duplicate request."""
    host = resolve_host(region_hint)
    tried = set()
    resp = None
    for _ in range(max_hops):
        if host in tried:
            break
        tried.add(host)
        url = f"https://{host}/{bucket_name}/"
        resp, err = anonymous_get(url, timeout, logger)
        if err is not None:
            return host, None, err

        next_host = None

        header_region = resp.headers.get("x-amz-bucket-region")
        if header_region:
            candidate = resolve_host(header_region)
            if candidate != host:
                next_host = candidate
                logger.debug(
                    f"  x-amz-bucket-region header on {host} says "
                    f"'{header_region}' -- retrying via {candidate}"
                )

        if next_host is None and resp.status_code in (301, 400):
            hint = parse_redirect_hint(resp.text)
            if hint:
                candidate = host_from_redirect_hint(hint, bucket_name)
                if candidate and candidate != host:
                    next_host = candidate
                    logger.debug(
                        f"  {resp.status_code} on {host}; body names "
                        f"{hint[0]}='{hint[1]}' -- retrying via {candidate}"
                    )

        if next_host:
            host = next_host
            continue
        break
    return host, resp, None


def parse_listing_for_objects(xml_text):
    """Parse an S3 ListBucketResult XML body into (key, size) tuples,
    skipping zero-byte "folder marker" keys where possible."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []
    objects = []
    for c in root.findall("s3:Contents", S3_NAMESPACE):
        key_el = c.find("s3:Key", S3_NAMESPACE)
        size_el = c.find("s3:Size", S3_NAMESPACE)
        if key_el is None or key_el.text is None:
            continue
        key = key_el.text
        try:
            size = int(size_el.text) if size_el is not None and size_el.text else 0
        except ValueError:
            size = 0
        if key.endswith("/"):
            continue
        objects.append((key, size))
    return objects


def choose_small_random_object(candidates):
    """From a list of (key, size) tuples, pick a random object biased toward
    small size (so downloads stay cheap/fast), preferring a non-empty object.

    A zero-byte object still fully exercises the HTTP status-code logic (S3
    returns the same status codes regardless of body size), so it's not
    "wrong" to pick one -- but a real file is a more convincing/reportable
    proof of exposure, so we search the *entire* candidate list for a
    non-zero object before ever falling back to a zero-byte one, rather than
    only looking within the 10 smallest objects."""
    if not candidates:
        return None, None
    nonzero_all = [c for c in candidates if c[1] > 0]
    if nonzero_all:
        ordered = sorted(nonzero_all, key=lambda kv: kv[1])
    else:
        ordered = sorted(candidates, key=lambda kv: kv[1])
    pool = ordered[: min(10, len(ordered))]
    return random.choice(pool)


def test_index_public(bucket_name, region, timeout, logger):
    """Resolve the working endpoint for this bucket and evaluate whether its
    object index is viewable by anyone with no credentials. Returns
    (is_public, listing_xml_or_None, note_or_None, raw_result, resolved_host)
    -- the resolved host is passed on to test_object_access so the file
    checks don't have to re-discover it (or re-trigger the same 301)."""
    host, resp, err = resolve_working_host(bucket_name, region, timeout, logger)
    if err is not None:
        return None, None, f"Anonymous index check error: {err}", err, host
    if resp is None:
        return None, None, f"Index check produced no response via {host}", f"no response via {host}", host
    if resp.status_code == 200 and "<ListBucketResult" in resp.text:
        return True, resp.text, None, f"200 via {host}", host
    if resp.status_code in (403, 401):
        return False, None, None, f"{resp.status_code} via {host}", host
    if resp.status_code == 404:
        return False, None, "Index check returned 404 (unexpected for an existing bucket)", f"404 via {host}", host
    header_region = resp.headers.get("x-amz-bucket-region", "not present in response")
    snippet = (resp.text or "")[:500].replace("\n", " ")
    return (None, None,
            f"Index check returned unexpected HTTP {resp.status_code} via {host} "
            f"(x-amz-bucket-region header: {header_region})",
            f"HTTP {resp.status_code} via {host} (x-amz-bucket-region: {header_region}): {snippet}", host)


def test_object_access(bucket_name, key, host, timeout, delay, logger):
    """Two independent anonymous tests on one specific object, both issued
    against the already-resolved working `host` for this bucket (see
    resolve_working_host / test_index_public):
       1) HTTPS, no credentials  -> is the object publicly downloadable at all
       2) plain HTTP, no credentials -> is it retrievable over an unencrypted
          channel (rather than being redirected/forced to HTTPS)
    """
    notes = []
    encoded_key = quote(key, safe="/")
    https_url = f"https://{host}/{bucket_name}/{encoded_key}"
    http_url = f"http://{host}/{bucket_name}/{encoded_key}"

    # 1) HTTPS, unauthenticated
    https_public = None
    resp, err = anonymous_get(https_url, timeout, logger)
    if err is not None:
        notes.append(f"HTTPS object check error: {err}")
        https_raw = err
    elif resp.status_code == 200:
        https_public = True
        https_raw = f"200 via {host}"
    elif resp.status_code in (401, 403):
        https_public = False
        https_raw = f"{resp.status_code} via {host}"
    elif resp.status_code in (301, 400):
        # The bucket-level redirect should already have resolved `host`
        # correctly; hitting this on a specific object usually means the
        # object itself needs a further hop (rare). Record it plainly,
        # including the region header, rather than silently guessing again.
        header_region = resp.headers.get("x-amz-bucket-region", "not present in response")
        notes.append(f"HTTPS object check unexpected HTTP {resp.status_code} via {host} "
                      f"(bucket-level host resolution did not carry over cleanly; "
                      f"x-amz-bucket-region: {header_region})")
        https_raw = f"HTTP {resp.status_code} via {host} (x-amz-bucket-region: {header_region}): {(resp.text or '')[:500]}"
    else:
        notes.append(f"HTTPS object check unexpected HTTP {resp.status_code} via {host}")
        https_raw = f"HTTP {resp.status_code} via {host}: {(resp.text or '')[:500]}"

    time.sleep(delay)

    # 2) Plain HTTP, unauthenticated -- must actually complete over HTTP,
    #    not be silently upgraded to HTTPS by a redirect. Same resolved host.
    http_unencrypted = None
    resp2, err2 = anonymous_get(http_url, timeout, logger)
    if err2 is not None:
        notes.append(f"HTTP object check error: {err2}")
        http_raw = err2
    else:
        final_scheme = urlparse(resp2.url).scheme
        if resp2.status_code == 200 and final_scheme == "http":
            http_unencrypted = True
            http_raw = f"200 via {host} (stayed HTTP)"
        elif resp2.status_code == 200 and final_scheme == "https":
            http_unencrypted = False
            notes.append("Plain-HTTP request was redirected to HTTPS -- object not retrievable over an unencrypted channel")
            http_raw = f"200 via {host} (redirected to HTTPS)"
        elif resp2.status_code in (401, 403):
            http_unencrypted = False
            http_raw = f"{resp2.status_code} via {host}"
        else:
            notes.append(f"HTTP object check unexpected HTTP {resp2.status_code} via {host}")
            http_raw = f"HTTP {resp2.status_code} via {host}: {(resp2.text or '')[:500]}"

    return https_public, http_unencrypted, notes, https_raw, http_raw, https_url, http_url


# --------------------------------------------------------------------------
# Risk classification
# --------------------------------------------------------------------------

def compute_risk(row):
    if row["index_publicly_listable_anonymous"] is True or row["file_public_no_auth_https"] is True:
        risk = "CRITICAL - Publicly Accessible"
        if row["file_public_http_unencrypted"] is True:
            risk += " (also unencrypted HTTP)"
        return risk
    if row["file_public_http_unencrypted"] is True:
        return "HIGH - Unencrypted Transport Exposure"
    if row["bucket_policy_public"] == "True" or row["acl_public_grant"] == "True":
        return "CRITICAL - Public per API Configuration"
    all_unknown = (
        row["index_publicly_listable_anonymous"] is None
        and row["file_public_no_auth_https"] is None
        and row["file_public_http_unencrypted"] is None
    )
    if all_unknown:
        return "UNKNOWN - Unable to Verify"
    return "OK - No Public Access Detected"


# --------------------------------------------------------------------------
# Per-bucket / per-profile orchestration
# --------------------------------------------------------------------------

def assess_bucket(s3_client, account_id, profile, bucket_name, args, logger):
    logger.info(f"[{profile}] Checking bucket: {bucket_name}")
    row = {fn: "" for fn in FIELDNAMES}
    row["timestamp_utc"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    row["aws_account_id"] = account_id
    row["profile"] = profile
    row["bucket_name"] = bucket_name

    notes = []

    region = get_bucket_region(s3_client, bucket_name, logger)
    row["region"] = region
    logger.debug(f"  Region: {region}")

    config_status, cfg = check_bucket_configuration(s3_client, bucket_name, logger)
    row["config_api_status"] = config_status
    row["public_access_block"] = cfg["public_access_block"]
    row["bucket_policy_public"] = cfg["bucket_policy_public"]
    row["acl_public_grant"] = cfg["acl_public_grant"]
    row["encryption_status"] = cfg["encryption_status"]
    logger.debug(f"  Config API status: {config_status} -> {cfg}")

    can_list_api, api_objects = list_objects_via_api(s3_client, bucket_name, args.max_keys, logger)
    row["role_can_list_objects_api"] = str(can_list_api)

    index_public, anon_listing_xml, idx_note, idx_raw, resolved_host = test_index_public(
        bucket_name, region, args.timeout, logger
    )
    row["index_publicly_listable_anonymous"] = index_public
    row["index_check_raw_result"] = idx_raw
    if idx_note:
        notes.append(idx_note)
    logger.debug(f"  Anonymous index public: {index_public} ({idx_raw}); resolved host: {resolved_host}")

    time.sleep(args.delay)

    # Prefer the authenticated API listing (more reliable / complete) to
    # choose a test object; fall back to the anonymous listing if the API
    # listing was denied but the bucket happens to be anonymously listable.
    candidate_key, candidate_size, source = None, None, None
    if api_objects:
        candidate_key, candidate_size = choose_small_random_object(api_objects)
        source = "authenticated API listing (ListObjectsV2)"
    elif anon_listing_xml:
        anon_objects = parse_listing_for_objects(anon_listing_xml)
        candidate_key, candidate_size = choose_small_random_object(anon_objects)
        source = "anonymous public listing"

    row["tested_file_source"] = source or "N/A"

    if candidate_key:
        row["tested_file"] = candidate_key
        row["tested_file_size_bytes"] = candidate_size
        notes.append(f"Tested object: {candidate_key} ({candidate_size} bytes) via {source}")
        logger.info(f"    Selected test object: {candidate_key} ({candidate_size} bytes)")

        https_public, http_unencrypted, obj_notes, https_raw, http_raw, https_url, http_url = test_object_access(
            bucket_name, candidate_key, resolved_host, args.timeout, args.delay, logger
        )
        row["tested_file_url_https"] = https_url
        row["tested_file_url_http"] = http_url
        row["file_public_no_auth_https"] = https_public
        row["file_https_check_raw_result"] = https_raw
        row["file_public_http_unencrypted"] = http_unencrypted
        row["file_http_check_raw_result"] = http_raw
        notes.extend(obj_notes)
        logger.debug(f"  File public (HTTPS, no auth): {https_public} ({https_raw}); "
                     f"File public (HTTP, unencrypted): {http_unencrypted} ({http_raw})")
    else:
        row["tested_file"] = "N/A"
        row["tested_file_size_bytes"] = "N/A"
        row["tested_file_url_https"] = "N/A"
        row["tested_file_url_http"] = "N/A"
        row["file_public_no_auth_https"] = None
        row["file_public_http_unencrypted"] = None
        notes.append(
            "No object available to test: role's ListObjectsV2 was denied/empty "
            "and the bucket is not anonymously listable"
        )

    row["risk_level"] = compute_risk(row)
    row["notes"] = "; ".join(notes)

    logger.info(f"    -> {row['risk_level']}")
    return row


def write_row(csv_writer, row):
    csv_writer.writerow(row)
    if _csv_file_handle:
        _csv_file_handle.flush()


def process_profile(profile, args, csv_writer, logger):
    logger.info(f"=== Starting profile: {profile} ===")
    try:
        session = boto3.Session(profile_name=profile)
    except botocore.exceptions.ProfileNotFound as e:
        logger.error(f"[{profile}] Profile not found: {e}")
        return
    except Exception as e:
        logger.error(f"[{profile}] Failed to create session: {e}")
        return

    region_hint = session.region_name or "us-east-1"
    boto_cfg = BotoConfig(retries={"max_attempts": 3, "mode": "standard"})

    try:
        sts_client = session.client("sts", region_name=region_hint, config=boto_cfg)
        identity = sts_client.get_caller_identity()
        account_id = identity["Account"]
        arn = identity.get("Arn", "unknown")
        logger.info(f"[{profile}] Authenticated as {arn} (Account: {account_id})")
    except Exception as e:
        logger.error(f"[{profile}] Unable to call STS GetCallerIdentity (invalid/expired credentials?): {e}")
        return

    try:
        s3_client = session.client("s3", region_name=region_hint, config=boto_cfg)
        buckets = s3_client.list_buckets().get("Buckets", [])
    except botocore.exceptions.ClientError as e:
        logger.error(f"[{profile}] Unable to list buckets ({error_code(e)}): {e}")
        return
    except Exception as e:
        logger.error(f"[{profile}] Unable to list buckets: {e}")
        return

    logger.info(f"[{profile}] {len(buckets)} bucket(s) found in account {account_id}")

    if not buckets:
        return

    with alive_bar(len(buckets), title=f"{profile}", enrich_print=False) as bar:
        for bucket in buckets:
            bucket_name = bucket["Name"]
            try:
                row = assess_bucket(s3_client, account_id, profile, bucket_name, args, logger)
            except Exception as e:
                logger.exception(f"[{profile}] Unhandled error assessing bucket {bucket_name}: {e}")
                row = {fn: "" for fn in FIELDNAMES}
                row.update({
                    "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "aws_account_id": account_id,
                    "profile": profile,
                    "bucket_name": bucket_name,
                    "risk_level": "ERROR",
                    "notes": f"Unhandled exception during assessment: {e}",
                })
            write_row(csv_writer, row)
            SUMMARY_ROWS.append(row)
            bar()
            time.sleep(args.delay)

    logger.info(f"=== Finished profile: {profile} ===")


# --------------------------------------------------------------------------
# STDOUT summary
# --------------------------------------------------------------------------

def print_summary_table():
    if not SUMMARY_ROWS:
        print("\nNo buckets were assessed.")
        return

    headers = ["Account", "Bucket", "Region", "Index\nPublic", "File Public\n(HTTPS)",
               "File Public\n(HTTP)", "Risk"]
    table_rows = []
    for r in SUMMARY_ROWS:
        table_rows.append([
            r["aws_account_id"],
            r["bucket_name"],
            r["region"],
            r["index_publicly_listable_anonymous"],
            r["file_public_no_auth_https"],
            r["file_public_http_unencrypted"],
            r["risk_level"],
        ])

    print("\n" + "=" * 100)
    print("S3 PUBLIC EXPOSURE ASSESSMENT -- SUMMARY")
    print("=" * 100)
    if HAVE_TABULATE:
        print(tabulate(table_rows, headers=headers, tablefmt="grid"))
    else:
        col_widths = [max(len(str(row[i])) for row in ([headers] + table_rows)) for i in range(len(headers))]
        def fmt_row(cells):
            return " | ".join(str(c).ljust(col_widths[i]) for i, c in enumerate(cells))
        print(fmt_row(headers))
        print("-+-".join("-" * w for w in col_widths))
        for row in table_rows:
            print(fmt_row(row))

    total = len(SUMMARY_ROWS)
    critical = sum(1 for r in SUMMARY_ROWS if r["risk_level"].startswith("CRITICAL"))
    high = sum(1 for r in SUMMARY_ROWS if r["risk_level"].startswith("HIGH"))
    unknown = sum(1 for r in SUMMARY_ROWS if r["risk_level"].startswith("UNKNOWN"))
    ok = sum(1 for r in SUMMARY_ROWS if r["risk_level"].startswith("OK"))
    print(f"\nTotal buckets assessed: {total}")
    print(f"  CRITICAL (public access confirmed): {critical}")
    print(f"  HIGH (unencrypted transport exposure): {high}")
    print(f"  UNKNOWN (unable to verify): {unknown}")
    print(f"  OK (no public access detected): {ok}")


# --------------------------------------------------------------------------
# Argument parsing / main
# --------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="Empirically validate S3 bucket public exposure (index listing, "
                    "unauthenticated object access, and unencrypted HTTP access), "
                    "independent of whether the operator's IAM role can read bucket "
                    "configuration directly."
    )
    profile_group = parser.add_mutually_exclusive_group(required=True)
    profile_group.add_argument(
        "--profile", nargs="+", metavar="PROFILE",
        help="One or more AWS CLI profile names to assess."
    )
    profile_group.add_argument(
        "--all-profiles", action="store_true",
        help="Assess every profile found in the AWS credentials file."
    )
    parser.add_argument(
        "--credentials-file", default=str(Path.home() / ".aws" / "credentials"),
        help="Path to the AWS credentials file (default: ~/.aws/credentials). "
             "Only used with --all-profiles."
    )
    parser.add_argument(
        "--output-dir", default=".",
        help="Directory to write the CSV and log files into (default: current directory)."
    )
    parser.add_argument(
        "--timeout", type=float, default=10.0,
        help="HTTP request timeout in seconds for anonymous checks (default: 10)."
    )
    parser.add_argument(
        "--delay", type=float, default=0.25,
        help="Delay in seconds between requests, to stay polite/avoid throttling (default: 0.25)."
    )
    parser.add_argument(
        "--max-keys", type=int, default=1000,
        help="Max objects to request per authenticated ListObjectsV2 call (default: 1000)."
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Print debug-level detail to STDOUT as well as the log file."
    )
    return parser.parse_args()


def main():
    global _csv_file_handle

    args = parse_args()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = out_dir / f"s3_assessment_{ts}.csv"
    log_path = out_dir / f"s3_assessment_{ts}.log"

    logger = build_logger(log_path, args.verbose)

    def _handle_sigint(signum, frame):
        logger.warning("Interrupted by user (Ctrl+C) -- flushing results collected so far.")
        if _csv_file_handle:
            _csv_file_handle.flush()
            _csv_file_handle.close()
        print_summary_table()
        print(f"\nPartial CSV: {csv_path}")
        print(f"Log file:    {log_path}")
        sys.exit(130)

    signal.signal(signal.SIGINT, _handle_sigint)

    logger.info(f"S3 Public Exposure Assessment v{SCRIPT_VERSION} starting")
    logger.info(f"Run parameters: {vars(args)}")
    print(f"S3 Public Exposure Assessment v{SCRIPT_VERSION}")
    print(f"Log file: {log_path}")
    print(f"CSV file: {csv_path}\n")

    if args.all_profiles:
        profiles = get_profiles_from_credentials_file(Path(args.credentials_file), logger)
        if not profiles:
            logger.error("No profiles discovered; nothing to do.")
            sys.exit(1)
    else:
        profiles = args.profile

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        _csv_file_handle = f
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        f.flush()

        for profile in profiles:
            process_profile(profile, args, writer, logger)

    logger.info("All profiles processed.")
    print_summary_table()
    print(f"\nDetailed results: {csv_path}")
    print(f"Full log:         {log_path}")


if __name__ == "__main__":
    main()

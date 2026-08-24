#!/usr/bin/env python3
"""
MergeCloudfoxReports.py

Summarize and cross-reference multiple per-account CloudFox AWS reports
(produced by `cloudfox aws --all-profiles`) into one master triage report
for a pentester, PLUS a "recon roadmap" of things worth investigating next
that aren't security findings by themselves.

CloudFox (as of the current release) writes output like this:

    <outdir>/cloudfox-output/aws/<profile>-<accountID>/
        csv/    <module>.csv    (one file per module, e.g. buckets.csv, secrets.csv, ...)
        table/  <module>.txt    (human-readable ASCII tables - not parsed by this script)
        loot/   <name>.txt      (free-form pullable command lists / dumped data -
                                  CloudFox itself already writes ready-to-run AWS CLI
                                  commands here for things like pulling Lambda code,
                                  ECR images, S3 bucket contents, secrets, etc.)

By default CloudFox writes to ~/.cloudfox/cloudfox-output, so that is the
default here too (matching what `cloudfox aws --all-profiles` produces with
no --outdir override).

This script does NOT restate all of the raw data - each account's original
CSV/table/loot output is still the source of truth for deep investigation.
Instead it does two things:

PART 1 - Security findings triage (heuristic, not exhaustive):
  1. Walks every "<profile>-<accountID>" folder it can find under the given
     root (so it works whether you point it at cloudfox-output/, .cloudfox/,
     or a custom --outdir).
  2. Reads every module CSV for that account and tallies how many resources
     each module enumerated.
  3. Flags rows worth a pentester's attention using two kinds of heuristics:
       - column-name heuristics (a column called "Public?", "IsAdminRole?",
         "CanPrivEscToAdmin?", "External...", etc. with a truthy value)
       - text-pattern heuristics (0.0.0.0/0, ::/0, AdministratorAccess,
         wildcard IAM principals/actions, iam:PassRole, etc. anywhere in a row)
     plus a short list of modules where CloudFox's whole purpose IS the
     finding (secrets, cross-account role trusts, pmapper privesc paths) -
     every row from those modules is carried into the summary.
  4. Scans loot/ files for credential-shaped strings (AWS access key IDs,
     private key headers, password-like assignments) WITHOUT copying the
     matched secret text into the report - only the match type, file, and
     line number are recorded, so the report itself isn't a second place
     secrets can leak from.
  5. Cross-references flagged findings across all accounts so patterns
     that repeat account-to-account (e.g. "12 of 40 accounts have a
     publicly readable S3 bucket") jump out immediately.

PART 2 - Recon roadmap (not findings - things to go investigate next):
  6. Builds a deduplicated list of externally/internally facing IPs,
     hostnames, and URLs pulled from instances/ENIs/databases/endpoints/
     API Gateways/Route53, meant to be fed straight into a vulnerability
     scanner (scan_targets.csv).
  7. Builds inventories of S3 buckets, Lambda functions, and ECR repos
     across every account, marked with whether each one was already
     surfaced in the findings above (so you know what's genuinely
     unexamined vs. already flagged).
  8. Builds a list of CloudFormation stacks that have Parameters/Outputs
     worth pulling, and EC2 instances that have user data present -
     without copying the actual parameter/output/user-data content into
     this report (that content can carry real secrets; go read the
     account's own loot/cloudformation-data.txt or loot/instance-userdata.txt).
  9. Merges CloudFox's own per-account loot/*.txt command files (bucket
     pulls, Lambda code downloads, ECR pulls, EKS kubeconfigs, SNS/SQS
     commands, secrets retrieval commands, SSM/EC2-Instance-Connect
     commands, public/private IP lists, DNS records, endpoint URLs, ...)
     into one file per command type under roadmap/loot/, each section
     labeled with the account it came from. These are CloudFox's own
     generated commands, just consolidated - nothing new is invented here.

This is heuristic triage, not a complete audit - always go back to the
account's own csv/table/loot files for anything this script doesn't flag.

Outputs (written to --output, default "<reports_dir>/master-report"):
  master_report.html             single-file, filterable/sortable HTML triage report
  master_report.json             full aggregated data
  account_summary.csv            one row per account: modules run, resources seen, findings by severity
  priority_findings.csv          one row per flagged finding, across all accounts
  module_row_counts.csv          one row per (module, account): how many resources that module found
  scan_targets.csv               deduplicated IPs/hostnames/URLs to feed a vuln scanner
  s3_bucket_inventory.csv        every S3 bucket found, with an already_flagged column
  lambda_inventory.csv           every Lambda function found, with an already_flagged column
  ecr_inventory.csv              every ECR repo/image found
  cloudformation_inventory.csv   stacks with Parameters/Outputs worth pulling manually
  ec2_userdata_inventory.csv     instances with user data present (not the content itself)
  roadmap/loot/<name>.txt        CloudFox's own per-account recon commands, merged across accounts

Usage:
  python3 MergeCloudfoxReports.py
  python3 MergeCloudfoxReports.py ~/.cloudfox/cloudfox-output
  python3 MergeCloudfoxReports.py /path/to/cloudfox-output -o ./master-report

Requires: alive-progress (pip install alive-progress)
"""

import argparse
import csv
import html
import json
import os
import re
import sys
from collections import defaultdict

try:
    from alive_progress import alive_bar
except ImportError:
    sys.exit(
        "error: the 'alive-progress' package is required.\n"
        "Install it with: pip install alive-progress"
    )

DEFAULT_REPORTS_DIR = os.path.expanduser('~/.cloudfox/cloudfox-output')

# Directories named "<profile>-<12-digit-account-id>" are what CloudFox creates
# for each scanned AWS account/profile.
ACCOUNT_DIR_RE = re.compile(r'^(?P<profile>.+)-(?P<account_id>\d{12})$')

# Modules where every row IS a finding worth surfacing (keyword matched
# against the module/CSV base name, since CloudFox's exact file list can
# grow between releases).
ALWAYS_FLAG_MODULES = {
    'secrets': ('secret-found', 'high'),
    'privesc': ('privesc-path', 'high'),
    'role-trusts': ('cross-account-trust', 'medium'),
    'resource-trusts': ('cross-account-trust', 'medium'),
    'outbound-assumed-roles': ('cross-account-trust', 'medium'),
}

# Column-name heuristics: a column whose header matches one of these
# (case-insensitive) is treated as a risk flag when its value looks truthy.
# 'admin'/'privesc' catch CloudFox's own "IsAdminRole?" / "CanPrivEscToAdmin?"
# columns, which appear on instances, lambda, ecs-tasks, eks, codebuild,
# principals, workloads, and pmapper - one of the highest-signal columns
# CloudFox produces.
RISK_COLUMN_PATTERNS = ['public', 'external', 'anonymous', 'exposed', 'insecure',
                         'unauthenticated', 'admin', 'privesc']
TRUTHY_VALUES = {'yes', 'y', 'true', '1', 'public'}

# Column-agnostic text patterns: matched against every cell's text. Order
# matters only for readability; category names double as severities via
# PATTERN_SEVERITY below.
TEXT_PATTERNS = [
    (re.compile(r'0\.0\.0\.0/0'), 'open-to-internet-ipv4'),
    (re.compile(r'::/0'), 'open-to-internet-ipv6'),
    (re.compile(r'AdministratorAccess'), 'administrator-access-policy'),
    (re.compile(r'"(?:AWS|Principal)"\s*:\s*"\*"'), 'wildcard-principal'),
    (re.compile(r'"Action"\s*:\s*(?:"\*"|\[\s*"\*")'), 'wildcard-action'),
    (re.compile(r'iam:PassRole', re.IGNORECASE), 'passrole-permission'),
]

PATTERN_SEVERITY = {
    'open-to-internet-ipv4': 'medium',
    'open-to-internet-ipv6': 'medium',
    'administrator-access-policy': 'high',
    'wildcard-principal': 'high',
    'wildcard-action': 'high',
    'passrole-permission': 'medium',
}

# Loot-file credential scan. Values are never copied into the report - only
# the match type, file, and line number are recorded.
LOOT_PATTERNS = [
    (re.compile(r'\bAKIA[0-9A-Z]{16}\b'), 'aws-access-key-id-in-loot', 'high'),
    (re.compile(r'\bASIA[0-9A-Z]{16}\b'), 'aws-temp-access-key-id-in-loot', 'medium'),
    (re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----'), 'private-key-in-loot', 'high'),
    (re.compile(r'(?i)\b(password|passwd|secret[_-]?key|api[_-]?key)\s*[=:]\s*\S+'), 'credential-like-string-in-loot', 'medium'),
]
MAX_LOOT_BYTES = 10 * 1024 * 1024  # don't slurp huge loot dumps into memory

IDENTIFIER_COLUMNS = [
    'name', 'arn', 'resourcearn', 'rolearn', 'userarn', 'resource', 'bucket',
    'bucketname', 'rolename', 'username', 'functionname', 'instanceid',
    'domain', 'endpoint', 'queueurl', 'topicarn', 'id', 'identifier',
]

SEVERITY_ORDER = {'high': 3, 'medium': 2, 'low': 1}

# ---------------------------------------------------------------------------
# Recon roadmap configuration
# ---------------------------------------------------------------------------

# Modules we keep full rows for (not just counts/findings) so we can build
# standalone inventories of them, cross-referenced against findings above.
INVENTORY_MODULES = {'buckets', 'lambda', 'ecr', 'cloudformation'}

# Loot files that can contain actual extracted VALUES (CloudFormation stack
# parameters/outputs, decoded EC2 user data) rather than just resource
# identifiers or ready-to-run commands. These are inventoried (presence,
# size, identifiers) but never merged verbatim - go read the account's own
# copy for the actual content.
SUMMARY_ONLY_LOOT_FILES = {'instance-userdata.txt', 'cloudformation-data.txt'}

# Per-module extractors for scan_targets.csv: given a lowercase-keyed row,
# return a list of (target, target_type, public, context) tuples. 'public'
# is 'true' / 'false' / 'unknown' (a string, not bool, so a genuinely-unknown
# value never silently collapses to False when merged across sources).


def _extract_instances(row):
    out = []
    name = row.get('name', '')
    ext = (row.get('external ip') or '').strip()
    if ext and ext.lower() not in ('', 'none', 'n/a', 'null'):
        out.append((ext, 'ip', 'true', f'EC2 instance {name}'.strip()))
    inte = (row.get('internal ip') or '').strip()
    if inte and inte.lower() not in ('', 'none', 'n/a', 'null'):
        out.append((inte, 'ip', 'false', f'EC2 instance {name}'.strip()))
    return out


def _extract_eni(row):
    out = []
    ident = row.get('id', '')
    ext = (row.get('external ip') or '').strip()
    if ext and ext.lower() not in ('', 'none', 'n/a', 'null'):
        out.append((ext, 'ip', 'true', f'ENI {ident}'.strip()))
    inte = (row.get('internal ip') or '').strip()
    if inte and inte.lower() not in ('', 'none', 'n/a', 'null'):
        out.append((inte, 'ip', 'false', f'ENI {ident}'.strip()))
    return out


def _extract_databases(row):
    ep = (row.get('endpoint') or '').strip()
    if not ep:
        return []
    port = (row.get('port') or '').strip()
    target = f'{ep}:{port}' if port else ep
    engine = row.get('engine', '')
    name = row.get('name', '')
    return [(target, 'hostname', 'unknown', f'{engine} database {name}'.strip())]


def _extract_endpoints(row):
    ep = (row.get('endpoint') or '').strip()
    if not ep:
        return []
    public = 'true' if (row.get('public') or '').strip().lower() in TRUTHY_VALUES else 'false'
    service = row.get('service', '')
    return [(ep, 'hostname', public, f'{service} endpoint'.strip())]


def _extract_api_gw(row):
    ep = (row.get('endpoint') or '').strip()
    if not ep:
        return []
    public = 'true' if (row.get('public') or '').strip().lower() in TRUTHY_VALUES else 'false'
    name = row.get('name', '')
    return [(ep, 'url', public, f'API Gateway {name}'.strip())]


def _extract_route53(row):
    out = []
    rtype = (row.get('type') or '').strip().upper()
    if rtype not in ('A', 'AAAA', 'CNAME'):
        return out
    private = (row.get('privatezone') or '').strip().lower() in TRUTHY_VALUES
    public = 'false' if private else 'true'
    name = (row.get('name') or '').strip()
    value = (row.get('value') or '').strip()
    if name:
        out.append((name, 'hostname', public, f'Route53 {rtype} record'))
    if value and value != name:
        out.append((value, 'hostname-or-ip', public, f'Route53 {rtype} record value'))
    return out


TARGET_EXTRACTORS = {
    'instances': _extract_instances,
    'elastic-network-interfaces': _extract_eni,
    'databases': _extract_databases,
    'endpoints': _extract_endpoints,
    'api-gw': _extract_api_gw,
    'route53': _extract_route53,
}

USERDATA_BLOCK_RE = re.compile(
    r'Instance Arn:\s*(?P<arn>\S+)\s*\n'
    r'Region:\s*(?P<region>\S+)\s*\n'
    r'Instance Profile:\s*(?P<profile>.*?)\s*\n\s*\n'
    r'User Data:\s*\n(?P<userdata>.*?)(?=\n=+\s*\n|\Z)',
    re.DOTALL,
)


def discover_account_dirs(root):
    """Find every '<profile>-<accountID>' folder under root that has csv/ or table/ output."""
    found = []
    root = os.path.abspath(root)
    for dirpath, dirnames, _filenames in os.walk(root):
        base = os.path.basename(dirpath)
        m = ACCOUNT_DIR_RE.match(base)
        if m and (os.path.isdir(os.path.join(dirpath, 'csv')) or os.path.isdir(os.path.join(dirpath, 'table'))):
            found.append({
                'dir': dirpath,
                'profile': m.group('profile'),
                'account_id': m.group('account_id'),
            })
            dirnames[:] = []  # don't descend further into an account's own folder
    return sorted(found, key=lambda a: (a['profile'], a['account_id']))


def pick_identifier(row_lower_map, fallback_row):
    for key in IDENTIFIER_COLUMNS:
        if key in row_lower_map and row_lower_map[key]:
            return row_lower_map[key]
    for v in fallback_row.values():
        if v:
            return v
    return ''


def scan_csv_module(csv_path, module_name, account):
    """Read one module CSV. Returns (row_count, findings, targets, inventory_rows)."""
    findings = []
    targets = []
    inventory_rows = []
    row_count = 0
    always_flag = next((v for kw, v in ALWAYS_FLAG_MODULES.items() if kw in module_name), None)
    extractor = TARGET_EXTRACTORS.get(module_name)
    keep_inventory = module_name in INVENTORY_MODULES

    try:
        with open(csv_path, newline='', encoding='utf-8', errors='replace') as f:
            reader = csv.DictReader(f)
            for row in reader:
                row_count += 1
                row = {k: (v or '') for k, v in row.items() if k is not None}
                row_lower = {(k or '').strip().lower(): v for k, v in row.items()}
                identifier = pick_identifier(row_lower, row)

                if extractor:
                    for target, ttype, public, context in extractor(row_lower):
                        targets.append({
                            'target': target, 'target_type': ttype, 'public': public,
                            'source_module': module_name, 'context': context,
                        })

                if keep_inventory:
                    inventory_rows.append({'_identifier': identifier, **row_lower})

                if always_flag:
                    category, severity = always_flag
                    findings.append({
                        'account_profile': account['profile'], 'account_id': account['account_id'],
                        'module': module_name, 'category': category, 'severity': severity,
                        'identifier': identifier, 'detail': f'row from {module_name}.csv',
                    })
                    continue  # don't double-flag rows from "always flag" modules

                row_flagged = False
                for col, val in row.items():
                    col_l = (col or '').strip().lower()
                    if any(p in col_l for p in RISK_COLUMN_PATTERNS) and val.strip().lower() in TRUTHY_VALUES:
                        findings.append({
                            'account_profile': account['profile'], 'account_id': account['account_id'],
                            'module': module_name, 'category': f'flagged-column:{col_l}', 'severity': 'medium',
                            'identifier': identifier, 'detail': f'{col}={val}',
                        })
                        row_flagged = True

                if not row_flagged:
                    for cell in row.values():
                        matched_any = False
                        for pattern, category in TEXT_PATTERNS:
                            if pattern.search(cell):
                                findings.append({
                                    'account_profile': account['profile'], 'account_id': account['account_id'],
                                    'module': module_name, 'category': category,
                                    'severity': PATTERN_SEVERITY.get(category, 'medium'),
                                    'identifier': identifier, 'detail': f'matched "{category}" pattern',
                                })
                                matched_any = True
                        if matched_any:
                            break
    except Exception as e:
        return 0, [{
            'account_profile': account['profile'], 'account_id': account['account_id'],
            'module': module_name, 'category': 'parse-error', 'severity': 'low',
            'identifier': os.path.basename(csv_path), 'detail': str(e),
        }], [], []

    return row_count, findings, targets, inventory_rows


def scan_loot(loot_dir, account):
    """List loot files and flag credential-shaped strings without copying secret text."""
    inventory = []
    findings = []
    if not os.path.isdir(loot_dir):
        return inventory, findings

    for name in sorted(os.listdir(loot_dir)):
        path = os.path.join(loot_dir, name)
        if not os.path.isfile(path):
            continue
        try:
            size = os.path.getsize(path)
            line_count = 0
            bytes_read = 0
            seen_categories = set()
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                for line_no, line in enumerate(f, 1):
                    line_count = line_no
                    bytes_read += len(line.encode('utf-8', errors='replace'))
                    if bytes_read > MAX_LOOT_BYTES:
                        break
                    for pattern, category, severity in LOOT_PATTERNS:
                        if pattern.search(line):
                            key = (category, line_no)
                            if key not in seen_categories:
                                seen_categories.add(key)
                                findings.append({
                                    'account_profile': account['profile'], 'account_id': account['account_id'],
                                    'module': 'loot', 'category': category, 'severity': severity,
                                    'identifier': name, 'detail': f'{name} line {line_no} (value redacted)',
                                })
            inventory.append({'file': name, 'bytes': size, 'lines': line_count})
        except Exception as e:
            inventory.append({'file': name, 'bytes': 0, 'lines': 0, 'error': str(e)})

    return inventory, findings


def scan_instance_userdata(loot_dir, account):
    """Parse loot/instance-userdata.txt for which instances have user data - not the content itself."""
    path = os.path.join(loot_dir, 'instance-userdata.txt')
    targets = []
    if not os.path.isfile(path):
        return targets
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
    except Exception:
        return targets
    for m in USERDATA_BLOCK_RE.finditer(content):
        targets.append({
            'account_profile': account['profile'], 'account_id': account['account_id'],
            'instance_arn': m.group('arn'), 'region': m.group('region'),
            'instance_profile': m.group('profile').strip(),
            'userdata_bytes': len(m.group('userdata').encode('utf-8', errors='replace')),
        })
    return targets


def collect_account(account):
    csv_dir = os.path.join(account['dir'], 'csv')
    modules = {}
    findings = []
    targets = []
    inventory = defaultdict(list)

    if os.path.isdir(csv_dir):
        for fname in sorted(os.listdir(csv_dir)):
            if not fname.endswith('.csv'):
                continue
            module_name = fname[:-4]
            row_count, module_findings, module_targets, module_inventory = scan_csv_module(
                os.path.join(csv_dir, fname), module_name, account)
            modules[module_name] = row_count
            findings.extend(module_findings)
            for t in module_targets:
                t['account_profile'] = account['profile']
                t['account_id'] = account['account_id']
                targets.append(t)
            if module_inventory:
                inventory[module_name] = module_inventory

    loot_dir = os.path.join(account['dir'], 'loot')
    loot_inventory, loot_findings = scan_loot(loot_dir, account)
    findings.extend(loot_findings)
    userdata_targets = scan_instance_userdata(loot_dir, account)

    severity_counts = {'high': 0, 'medium': 0, 'low': 0}
    for f in findings:
        severity_counts[f.get('severity', 'low')] = severity_counts.get(f.get('severity', 'low'), 0) + 1

    # (module, identifier-lowercased) pairs already surfaced as findings, so
    # the roadmap inventories below can mark "already covered above" instead
    # of repeating it as if it were new.
    flagged_keys = {(f['module'], (f['identifier'] or '').strip().lower()) for f in findings}

    return {
        'profile': account['profile'],
        'account_id': account['account_id'],
        'dir': account['dir'],
        'modules': modules,
        'total_resources': sum(modules.values()),
        'loot_inventory': loot_inventory,
        'findings': findings,
        'severity_counts': severity_counts,
        'targets': targets,
        'inventory': inventory,
        'userdata_targets': userdata_targets,
        'flagged_keys': flagged_keys,
    }


def write_account_summary_csv(path, accounts):
    fields = ['profile', 'account_id', 'modules_run', 'total_resources_enumerated',
              'findings_high', 'findings_medium', 'findings_low', 'loot_files']
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(fields)
        for a in accounts:
            sc = a['severity_counts']
            w.writerow([a['profile'], a['account_id'], len(a['modules']), a['total_resources'],
                        sc.get('high', 0), sc.get('medium', 0), sc.get('low', 0), len(a['loot_inventory'])])


def write_priority_findings_csv(path, accounts):
    fields = ['severity', 'account_profile', 'account_id', 'module', 'category', 'identifier', 'detail']
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(fields)
        all_findings = [fnd for a in accounts for fnd in a['findings']]
        all_findings.sort(key=lambda x: -SEVERITY_ORDER.get(x['severity'], 0))
        for fnd in all_findings:
            w.writerow([fnd['severity'], fnd['account_profile'], fnd['account_id'], fnd['module'],
                        fnd['category'], fnd['identifier'], fnd['detail']])


def write_module_row_counts_csv(path, accounts):
    fields = ['module', 'account_profile', 'account_id', 'row_count']
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(fields)
        for a in accounts:
            for module, count in sorted(a['modules'].items()):
                w.writerow([module, a['profile'], a['account_id'], count])


def build_finding_index(accounts):
    """Cross-account index: one entry per (module, category), listing which accounts hit it."""
    index = {}
    for a in accounts:
        for fnd in a['findings']:
            key = f"{fnd['module']}::{fnd['category']}"
            entry = index.setdefault(key, {
                'module': fnd['module'], 'category': fnd['category'], 'severity': fnd['severity'],
                'accounts': {}, 'total_count': 0,
            })
            acct_key = f"{fnd['account_profile']}-{fnd['account_id']}"
            entry['accounts'][acct_key] = entry['accounts'].get(acct_key, 0) + 1
            entry['total_count'] += 1
    return index


# ---------------------------------------------------------------------------
# Recon roadmap: scan targets + inventories + merged loot commands
# ---------------------------------------------------------------------------

def build_scan_targets(accounts):
    """Dedup (account, target) across every module that contributed it."""
    dedup = {}
    for a in accounts:
        for t in a['targets']:
            key = (t['account_id'], t['target'])
            entry = dedup.setdefault(key, {
                'account_profile': t['account_profile'], 'account_id': t['account_id'],
                'target': t['target'], 'target_type': t['target_type'],
                'public': 'unknown', 'source_modules': set(), 'context': set(),
            })
            entry['source_modules'].add(t['source_module'])
            entry['context'].add(t['context'])
            if t['public'] == 'true':
                entry['public'] = 'true'
            elif t['public'] == 'false' and entry['public'] != 'true':
                entry['public'] = 'false'

    result = []
    for entry in dedup.values():
        entry['source_modules'] = ', '.join(sorted(entry['source_modules']))
        entry['context'] = '; '.join(sorted(c for c in entry['context'] if c))
        result.append(entry)
    result.sort(key=lambda e: (e['public'] != 'true', e['account_profile'], e['target']))
    return result


def write_scan_targets_csv(path, targets):
    fields = ['target', 'target_type', 'public', 'account_profile', 'account_id', 'source_modules', 'context']
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(fields)
        for t in targets:
            w.writerow([t['target'], t['target_type'], t['public'], t['account_profile'],
                        t['account_id'], t['source_modules'], t['context']])


def write_bucket_inventory_csv(path, accounts):
    fields = ['account_profile', 'account_id', 'name', 'region', 'public', 'resource_policy_summary', 'already_flagged']
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(fields)
        n = 0
        for a in accounts:
            for row in a['inventory'].get('buckets', []):
                already = ('buckets', row['_identifier'].strip().lower()) in a['flagged_keys']
                w.writerow([a['profile'], a['account_id'], row.get('name', ''), row.get('region', ''),
                            row.get('public?', row.get('public', '')), row.get('resource policy summary', ''),
                            already])
                n += 1
        return n


def write_lambda_inventory_csv(path, accounts):
    fields = ['account_profile', 'account_id', 'name', 'arn', 'role', 'is_admin_role',
              'can_privesc_to_admin', 'already_flagged']
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(fields)
        n = 0
        for a in accounts:
            for row in a['inventory'].get('lambda', []):
                already = ('lambda', row['_identifier'].strip().lower()) in a['flagged_keys']
                w.writerow([a['profile'], a['account_id'], row.get('name', ''), row.get('arn', ''),
                            row.get('role', ''), row.get('isadminrole?', ''), row.get('canprivesctoadmin?', ''),
                            already])
                n += 1
        return n


def write_ecr_inventory_csv(path, accounts):
    fields = ['account_profile', 'account_id', 'name', 'uri', 'pushed_at', 'image_tags', 'image_size']
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(fields)
        n = 0
        for a in accounts:
            for row in a['inventory'].get('ecr', []):
                w.writerow([a['profile'], a['account_id'], row.get('name', ''), row.get('uri', ''),
                            row.get('pushedat', ''), row.get('imagetags', ''), row.get('imagesize', '')])
                n += 1
        return n


def write_cloudformation_inventory_csv(path, accounts):
    fields = ['account_profile', 'account_id', 'stack_name', 'region', 'role',
              'has_parameters', 'has_outputs', 'already_flagged']
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(fields)
        n = 0
        for a in accounts:
            for row in a['inventory'].get('cloudformation', []):
                has_params = bool((row.get('parameters') or '').strip())
                has_outputs = bool((row.get('outputs') or '').strip())
                if not (has_params or has_outputs):
                    continue  # nothing worth pulling for this stack
                already = ('cloudformation', row['_identifier'].strip().lower()) in a['flagged_keys']
                w.writerow([a['profile'], a['account_id'], row.get('name', ''), row.get('region', ''),
                            row.get('role', ''), has_params, has_outputs, already])
                n += 1
        return n


def write_ec2_userdata_csv(path, accounts):
    fields = ['account_profile', 'account_id', 'instance_arn', 'region', 'instance_profile', 'userdata_bytes']
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(fields)
        n = 0
        for a in accounts:
            for t in a['userdata_targets']:
                w.writerow([t['account_profile'], t['account_id'], t['instance_arn'], t['region'],
                            t['instance_profile'], t['userdata_bytes']])
                n += 1
        return n


def merge_loot_files(accounts, output_dir):
    """Merge CloudFox's own per-account loot/*.txt command files across accounts.

    These are CloudFox-generated ready-to-run recon commands (bucket pulls,
    Lambda code downloads, ECR pulls, EKS kubeconfigs, SNS/SQS commands,
    secrets retrieval, SSM/EC2-Instance-Connect commands, public/private IP
    lists, DNS records, endpoint URLs, ...). Files in SUMMARY_ONLY_LOOT_FILES
    are skipped here (they're inventoried elsewhere without their content,
    since they can carry actual secret/parameter values).
    """
    grouped = defaultdict(list)
    for a in accounts:
        loot_dir = os.path.join(a['dir'], 'loot')
        if not os.path.isdir(loot_dir):
            continue
        for fname in sorted(os.listdir(loot_dir)):
            if fname in SUMMARY_ONLY_LOOT_FILES or not fname.endswith('.txt'):
                continue
            fpath = os.path.join(loot_dir, fname)
            if not os.path.isfile(fpath):
                continue
            try:
                with open(fpath, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read().rstrip('\n')
            except Exception:
                continue
            if not content.strip():
                continue
            grouped[fname].append((f"{a['profile']}-{a['account_id']}", content))

    roadmap_dir = os.path.join(output_dir, 'roadmap', 'loot')
    os.makedirs(roadmap_dir, exist_ok=True)
    summary = {}
    for fname, entries in sorted(grouped.items()):
        out_lines = [
            f"# {fname} - merged from {len(entries)} account(s) by MergeCloudfoxReports.py",
            "# Content is CloudFox's own per-account output; only the merge is new.",
            "",
        ]
        for acct_label, content in entries:
            out_lines.append(f"########## ACCOUNT: {acct_label} ##########")
            out_lines.append(content)
            out_lines.append("")
        out_path = os.path.join(roadmap_dir, fname)
        with open(out_path, 'w', encoding='utf-8') as f:
            f.write("\n".join(out_lines))
        summary[fname] = {'accounts': len(entries), 'bytes': os.path.getsize(out_path)}
    return summary


HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>CloudFox Master Triage Report</title>
<style>
  :root {
    --bg: #f7f8fa; --panel: #ffffff; --text: #1b1f24; --muted: #5b6472;
    --border: #dde1e6; --high: #c0292a; --high-bg: #fdecec;
    --medium: #9a6400; --medium-bg: #fdf3dc; --low: #3d6b3d; --low-bg: #eaf3ea; --accent: #2f5fd6;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #14171b; --panel: #1d2126; --text: #e8eaed; --muted: #9aa4af;
      --border: #2c3238; --high: #ff6b6b; --high-bg: #3a1d1d;
      --medium: #f0b429; --medium-bg: #3a301a; --low: #7fbf7f; --low-bg: #1c2b1c; --accent: #6d9bff;
    }
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--text);
         font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
  header { padding: 24px 32px; border-bottom: 1px solid var(--border); }
  header h1 { margin: 0 0 4px; font-size: 1.4rem; }
  header p { margin: 0; color: var(--muted); font-size: 0.9rem; }
  main { padding: 24px 32px; max-width: 1500px; margin: 0 auto; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-bottom: 28px; }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 14px 16px; }
  .card .num { font-size: 1.6rem; font-weight: 600; }
  .card .label { color: var(--muted); font-size: 0.8rem; }
  section { margin-bottom: 32px; }
  h2 { font-size: 1.1rem; margin: 0 0 12px; }
  .table-scroll { overflow-x: auto; border-radius: 10px; }
  table { width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--border); border-radius: 10px; }
  th, td { text-align: left; padding: 9px 12px; border-bottom: 1px solid var(--border); font-size: 0.87rem; vertical-align: top; white-space: nowrap; }
  td.wrap { white-space: normal; }
  th { cursor: pointer; user-select: none; color: var(--muted); font-weight: 600; }
  th:hover { color: var(--text); }
  tr:last-child td { border-bottom: none; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 0.75rem; font-weight: 600; }
  .badge.high { background: var(--high-bg); color: var(--high); }
  .badge.medium { background: var(--medium-bg); color: var(--medium); }
  .badge.low { background: var(--low-bg); color: var(--low); }
  .controls { display: flex; gap: 10px; margin-bottom: 12px; flex-wrap: wrap; }
  input[type=text], select { padding: 7px 10px; border: 1px solid var(--border); border-radius: 6px;
         background: var(--panel); color: var(--text); font-size: 0.87rem; }
  input[type=text] { flex: 1; min-width: 200px; }
  .count-pill { font-size: 0.78rem; color: var(--muted); margin-left: 6px; }
  .muted { color: var(--muted); font-size: 0.85rem; }
  .roadmap-note { font-size: 0.85rem; color: var(--muted); margin: 0 0 12px; }
  td a, .roadmap-note a { color: var(--accent); text-decoration: none; }
  td a:hover, .roadmap-note a:hover { text-decoration: underline; }
</style>
</head>
<body>
<header>
  <h1>CloudFox Master Triage Report</h1>
  <p>Generated __GENERATED_AT__ &middot; __ACCOUNT_COUNT__ account(s) merged &middot; heuristic triage - always confirm against raw CloudFox output</p>
</header>
<main>
  <div class="cards" id="summary-cards"></div>

  <section>
    <h2>Accounts scanned</h2>
    <div class="table-scroll">
    <table id="accounts-table">
      <thead>
        <tr>
          <th data-key="profile">Profile</th>
          <th data-key="account_id">AWS Account ID</th>
          <th data-key="modules_run">Modules w/ Data</th>
          <th data-key="total_resources">Resources Enumerated</th>
          <th data-key="high">High</th>
          <th data-key="medium">Medium</th>
          <th data-key="low">Low</th>
        </tr>
      </thead>
      <tbody></tbody>
    </table>
    </div>
  </section>

  <section>
    <h2>Priority findings <span class="count-pill" id="findings-count"></span></h2>
    <div class="controls">
      <input type="text" id="search" placeholder="Search module, category, identifier...">
      <select id="severity-filter">
        <option value="">All severities</option>
        <option value="high">High only</option>
        <option value="medium">Medium only</option>
        <option value="low">Low only</option>
      </select>
      <select id="module-filter"><option value="">All modules</option></select>
      <select id="account-filter"><option value="">All accounts</option></select>
    </div>
    <div class="table-scroll">
    <table id="findings-table">
      <thead>
        <tr>
          <th data-key="severity">Severity</th>
          <th data-key="module">Module</th>
          <th data-key="category">Category</th>
          <th data-key="identifier">Resource</th>
          <th data-key="detail">Detail</th>
          <th data-key="account">Account</th>
        </tr>
      </thead>
      <tbody></tbody>
    </table>
    </div>
  </section>

  <section>
    <h2>Recon roadmap <span class="muted">(not findings - things to investigate next)</span></h2>
    <p class="roadmap-note">These aren't security issues by themselves - they're what's left to check. Full detail is in the linked CSV/text files next to this report, not restated here.</p>
    <div class="table-scroll">
      <table>
        <thead><tr><th>Artifact</th><th>What it is</th><th>Count</th></tr></thead>
        <tbody>
__ROADMAP_ROWS__
        </tbody>
      </table>
    </div>
  </section>

  <section>
    <h2>Module coverage matrix <span class="muted">(resources enumerated per module per account)</span></h2>
    <div class="table-scroll">
      <table id="matrix-table"><thead><tr></tr></thead><tbody></tbody></table>
    </div>
  </section>
</main>

<script>
const ACCOUNTS = __ACCOUNTS_JSON__;
const FINDINGS = __FINDINGS_JSON__;
const MATRIX = __MATRIX_JSON__; // {modules: [...], accounts: [...], rows: {module: {account: count}}}

function el(tag, attrs, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === 'text') e.textContent = v; else if (k === 'class' && v === '') { /* skip */ } else e.setAttribute(k, v);
  }
  children.forEach(c => { if (c !== null && c !== undefined) e.appendChild(c); });
  return e;
}
function badge(sev) { return el('span', { class: 'badge ' + sev, text: sev }); }

(function renderCards() {
  const totalResources = ACCOUNTS.reduce((s, a) => s + a.total_resources, 0);
  const high = ACCOUNTS.reduce((s, a) => s + a.severity_counts.high, 0);
  const medium = ACCOUNTS.reduce((s, a) => s + a.severity_counts.medium, 0);
  const cards = [
    ['Accounts', ACCOUNTS.length],
    ['Resources enumerated', totalResources],
    ['High severity findings', high],
    ['Medium severity findings', medium],
  ];
  const wrap = document.getElementById('summary-cards');
  cards.forEach(([label, num]) => {
    wrap.appendChild(el('div', { class: 'card' }, el('div', { class: 'num', text: num }), el('div', { class: 'label', text: label })));
  });
})();

let accountSort = { key: 'high', dir: -1 };
function acctVal(a, key) {
  if (key === 'modules_run') return a.modules_run;
  if (key === 'total_resources') return a.total_resources;
  if (['high', 'medium', 'low'].includes(key)) return a.severity_counts[key];
  return a[key];
}
function renderAccounts() {
  const tbody = document.querySelector('#accounts-table tbody');
  tbody.innerHTML = '';
  const rows = [...ACCOUNTS].sort((a, b) => {
    const ka = acctVal(a, accountSort.key), kb = acctVal(b, accountSort.key);
    if (ka < kb) return -1 * accountSort.dir;
    if (ka > kb) return 1 * accountSort.dir;
    return 0;
  });
  rows.forEach(a => {
    tbody.appendChild(el('tr', {},
      el('td', { text: a.profile }), el('td', { text: a.account_id }),
      el('td', { text: a.modules_run }), el('td', { text: a.total_resources }),
      el('td', {}, badge('high'), document.createTextNode(' ' + a.severity_counts.high)),
      el('td', {}, badge('medium'), document.createTextNode(' ' + a.severity_counts.medium)),
      el('td', {}, badge('low'), document.createTextNode(' ' + a.severity_counts.low)),
    ));
  });
}
document.querySelectorAll('#accounts-table th').forEach(th => th.addEventListener('click', () => {
  const key = th.dataset.key;
  accountSort.dir = (accountSort.key === key) ? -accountSort.dir : -1;
  accountSort.key = key;
  renderAccounts();
}));

let findingSort = { key: 'severity', dir: -1 };
const SEV_ORDER = { high: 3, medium: 2, low: 1 };
const modules = [...new Set(FINDINGS.map(f => f.module))].sort();
const accountNames = [...new Set(FINDINGS.map(f => f.account))].sort();
modules.forEach(m => document.getElementById('module-filter').appendChild(el('option', { value: m, text: m })));
accountNames.forEach(a => document.getElementById('account-filter').appendChild(el('option', { value: a, text: a })));

function currentFilters() {
  return {
    q: document.getElementById('search').value.trim().toLowerCase(),
    severity: document.getElementById('severity-filter').value,
    module: document.getElementById('module-filter').value,
    account: document.getElementById('account-filter').value,
  };
}
function renderFindings() {
  const { q, severity, module, account } = currentFilters();
  let rows = FINDINGS.filter(f => {
    if (severity && f.severity !== severity) return false;
    if (module && f.module !== module) return false;
    if (account && f.account !== account) return false;
    if (q && !(f.module + ' ' + f.category + ' ' + f.identifier + ' ' + f.detail + ' ' + f.account).toLowerCase().includes(q)) return false;
    return true;
  });
  rows.sort((a, b) => {
    let ka = findingSort.key === 'severity' ? SEV_ORDER[a.severity] : a[findingSort.key];
    let kb = findingSort.key === 'severity' ? SEV_ORDER[b.severity] : b[findingSort.key];
    if (ka < kb) return -1 * findingSort.dir;
    if (ka > kb) return 1 * findingSort.dir;
    return 0;
  });
  document.getElementById('findings-count').textContent = rows.length + ' of ' + FINDINGS.length;
  const tbody = document.querySelector('#findings-table tbody');
  tbody.innerHTML = '';
  rows.forEach(f => {
    tbody.appendChild(el('tr', {},
      el('td', {}, badge(f.severity)),
      el('td', { text: f.module }),
      el('td', { text: f.category }),
      el('td', { text: f.identifier, class: 'wrap' }),
      el('td', { text: f.detail, class: 'wrap' }),
      el('td', { text: f.account }),
    ));
  });
}
document.querySelectorAll('#findings-table th').forEach(th => th.addEventListener('click', () => {
  const key = th.dataset.key;
  findingSort.dir = (findingSort.key === key) ? -findingSort.dir : -1;
  findingSort.key = key;
  renderFindings();
}));
['search', 'severity-filter', 'module-filter', 'account-filter'].forEach(id =>
  document.getElementById(id).addEventListener('input', renderFindings));

function renderMatrix() {
  const theadRow = document.querySelector('#matrix-table thead tr');
  const tbody = document.querySelector('#matrix-table tbody');
  theadRow.innerHTML = ''; tbody.innerHTML = '';
  theadRow.appendChild(el('th', { text: 'Module' }));
  MATRIX.accounts.forEach(a => theadRow.appendChild(el('th', { text: a })));
  MATRIX.modules.forEach(m => {
    const row = el('tr', {}, el('td', { text: m }));
    MATRIX.accounts.forEach(a => {
      const v = (MATRIX.rows[m] && MATRIX.rows[m][a]) || 0;
      row.appendChild(el('td', { text: v || '' }));
    });
    tbody.appendChild(row);
  });
}

renderAccounts();
renderFindings();
renderMatrix();
</script>
</body>
</html>
"""


def render_roadmap_rows(roadmap_counts):
    """Server-rendered (non-JS) table rows for the recon roadmap section."""
    descriptions = {
        'scan_targets.csv': ('External/internal IPs, hostnames, and URLs enumerated - '
                              'feed straight into your vulnerability scanner.'),
        's3_bucket_inventory.csv': ('Every S3 bucket found. "already_flagged" marks the ones the '
                                    'findings above already cover; the rest are unexamined.'),
        'lambda_inventory.csv': ('Every Lambda function found, with IsAdminRole?/CanPrivEscToAdmin? '
                                  'carried through for quick triage.'),
        'ecr_inventory.csv': 'Every ECR repository/image found.',
        'cloudformation_inventory.csv': ('Stacks with Parameters or Outputs worth pulling manually - '
                                          'actual values are NOT duplicated here, see each account\'s own '
                                          'loot/cloudformation-data.txt.'),
        'ec2_userdata_inventory.csv': ('Instances that have user data present - the decoded content is '
                                        'NOT duplicated here, see each account\'s own loot/instance-userdata.txt.'),
        'roadmap/loot/': ('CloudFox\'s own ready-to-run recon commands (bucket pulls, Lambda/ECR pulls, '
                           'EKS kubeconfigs, secrets retrieval, SSM/EC2-Instance-Connect, IP/DNS lists, ...), '
                           'merged across every account, one file per command type.'),
    }
    rows = []
    for fname, count in roadmap_counts.items():
        if count == 0:
            continue
        desc = descriptions.get(fname, '')
        rows.append(
            f'<tr><td><a href="{html.escape(fname)}">{html.escape(fname)}</a></td>'
            f'<td class="wrap">{html.escape(desc)}</td><td>{count}</td></tr>'
        )
    return '\n'.join(rows) if rows else '<tr><td colspan="3" class="muted">Nothing to report.</td></tr>'


def render_html(accounts, finding_index, roadmap_counts):
    flat_accounts = [{
        'profile': a['profile'], 'account_id': a['account_id'],
        'modules_run': len(a['modules']), 'total_resources': a['total_resources'],
        'severity_counts': a['severity_counts'],
    } for a in accounts]

    flat_findings = []
    for a in accounts:
        acct_label = f"{a['profile']}-{a['account_id']}"
        for fnd in a['findings']:
            flat_findings.append({
                'account': acct_label, 'module': fnd['module'], 'category': fnd['category'],
                'severity': fnd['severity'], 'identifier': fnd['identifier'], 'detail': fnd['detail'],
            })

    all_modules = sorted({m for a in accounts for m in a['modules']})
    all_account_labels = [f"{a['profile']}-{a['account_id']}" for a in accounts]
    matrix_rows = {m: {} for m in all_modules}
    for a in accounts:
        acct_label = f"{a['profile']}-{a['account_id']}"
        for m, count in a['modules'].items():
            matrix_rows[m][acct_label] = count
    matrix = {'modules': all_modules, 'accounts': all_account_labels, 'rows': matrix_rows}

    def dump(obj):
        return json.dumps(obj).replace('</', '<\\/')

    out = HTML_TEMPLATE
    out = out.replace('__GENERATED_AT__', html.escape(__import__('time').strftime('%Y-%m-%d %H:%M %Z')))
    out = out.replace('__ACCOUNT_COUNT__', str(len(accounts)))
    out = out.replace('__ACCOUNTS_JSON__', dump(flat_accounts))
    out = out.replace('__FINDINGS_JSON__', dump(flat_findings))
    out = out.replace('__MATRIX_JSON__', dump(matrix))
    out = out.replace('__ROADMAP_ROWS__', render_roadmap_rows(roadmap_counts))
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('reports_dir', nargs='?', default=DEFAULT_REPORTS_DIR,
                         help=f'CloudFox output folder to scan (default: {DEFAULT_REPORTS_DIR})')
    parser.add_argument('-o', '--output', default=None,
                         help='Output folder (default: <reports_dir>/master-report)')
    args = parser.parse_args()

    reports_dir = os.path.abspath(os.path.expanduser(args.reports_dir))
    if not os.path.isdir(reports_dir):
        print(f"error: not a directory: {reports_dir}", file=sys.stderr)
        sys.exit(1)

    output_dir = os.path.abspath(args.output) if args.output else os.path.join(reports_dir, 'master-report')
    os.makedirs(output_dir, exist_ok=True)

    account_dirs = discover_account_dirs(reports_dir)
    if not account_dirs:
        print(f"error: no '<profile>-<accountID>' folders with csv/ or table/ output found under {reports_dir}",
              file=sys.stderr)
        sys.exit(1)

    accounts = []
    with alive_bar(len(account_dirs), title='Analyzing account data') as bar:
        for acct in account_dirs:
            bar.text = f"-> {acct['profile']}-{acct['account_id']}"
            accounts.append(collect_account(acct))
            bar()

    roadmap_counts = {}
    scan_targets_holder = {}

    def _build_scan_targets():
        scan_targets_holder['targets'] = build_scan_targets(accounts)

    def _write_scan_targets():
        targets = scan_targets_holder['targets']
        write_scan_targets_csv(os.path.join(output_dir, 'scan_targets.csv'), targets)
        roadmap_counts['scan_targets.csv'] = len(targets)

    def _write_bucket_inventory():
        roadmap_counts['s3_bucket_inventory.csv'] = write_bucket_inventory_csv(
            os.path.join(output_dir, 's3_bucket_inventory.csv'), accounts)

    def _write_lambda_inventory():
        roadmap_counts['lambda_inventory.csv'] = write_lambda_inventory_csv(
            os.path.join(output_dir, 'lambda_inventory.csv'), accounts)

    def _write_ecr_inventory():
        roadmap_counts['ecr_inventory.csv'] = write_ecr_inventory_csv(
            os.path.join(output_dir, 'ecr_inventory.csv'), accounts)

    def _write_cloudformation_inventory():
        roadmap_counts['cloudformation_inventory.csv'] = write_cloudformation_inventory_csv(
            os.path.join(output_dir, 'cloudformation_inventory.csv'), accounts)

    def _write_userdata_inventory():
        roadmap_counts['ec2_userdata_inventory.csv'] = write_ec2_userdata_csv(
            os.path.join(output_dir, 'ec2_userdata_inventory.csv'), accounts)

    def _merge_loot():
        loot_summary = merge_loot_files(accounts, output_dir)
        roadmap_counts['roadmap/loot/'] = len(loot_summary)

    roadmap_steps = [
        ('cross-referencing scan targets across accounts', _build_scan_targets),
        ('writing scan_targets.csv', _write_scan_targets),
        ('writing s3_bucket_inventory.csv', _write_bucket_inventory),
        ('writing lambda_inventory.csv', _write_lambda_inventory),
        ('writing ecr_inventory.csv', _write_ecr_inventory),
        ('writing cloudformation_inventory.csv', _write_cloudformation_inventory),
        ('writing ec2_userdata_inventory.csv', _write_userdata_inventory),
        ('merging per-account loot commands', _merge_loot),
    ]
    with alive_bar(len(roadmap_steps), title='Building recon roadmap') as bar:
        for label, step in roadmap_steps:
            bar.text = f'-> {label}'
            step()
            bar()

    finding_index = {}

    def _build_index():
        nonlocal finding_index
        finding_index = build_finding_index(accounts)

    def _write_json():
        master = {'accounts': accounts, 'findings_by_category': finding_index,
                   'scan_targets': scan_targets_holder['targets']}
        with open(os.path.join(output_dir, 'master_report.json'), 'w', encoding='utf-8') as f:
            json.dump(master, f, indent=2, sort_keys=True, default=lambda o: list(o) if isinstance(o, set) else str(o))

    def _write_account_csv():
        write_account_summary_csv(os.path.join(output_dir, 'account_summary.csv'), accounts)

    def _write_findings_csv():
        write_priority_findings_csv(os.path.join(output_dir, 'priority_findings.csv'), accounts)

    def _write_module_csv():
        write_module_row_counts_csv(os.path.join(output_dir, 'module_row_counts.csv'), accounts)

    def _write_html():
        with open(os.path.join(output_dir, 'master_report.html'), 'w', encoding='utf-8') as f:
            f.write(render_html(accounts, finding_index, roadmap_counts))

    report_steps = [
        ('cross-referencing findings across accounts', _build_index),
        ('writing master_report.json', _write_json),
        ('writing account_summary.csv', _write_account_csv),
        ('writing priority_findings.csv', _write_findings_csv),
        ('writing module_row_counts.csv', _write_module_csv),
        ('writing master_report.html', _write_html),
    ]
    with alive_bar(len(report_steps), title='Generating summary report') as bar:
        for label, step in report_steps:
            bar.text = f'-> {label}'
            step()
            bar()

    total_resources = sum(a['total_resources'] for a in accounts)
    total_high = sum(a['severity_counts']['high'] for a in accounts)
    total_medium = sum(a['severity_counts']['medium'] for a in accounts)
    print(f"Merged {len(accounts)} account(s): {total_resources} resources enumerated, "
          f"{total_high} high / {total_medium} medium severity findings flagged.")
    print(f"Recon roadmap: {roadmap_counts}")
    print(f"Output written to: {output_dir}")
    for fname in ('master_report.html', 'master_report.json', 'account_summary.csv',
                  'priority_findings.csv', 'module_row_counts.csv', 'scan_targets.csv',
                  's3_bucket_inventory.csv', 'lambda_inventory.csv', 'ecr_inventory.csv',
                  'cloudformation_inventory.csv', 'ec2_userdata_inventory.csv', 'roadmap/loot/'):
        print(f"  - {os.path.join(output_dir, fname)}")


if __name__ == '__main__':
    main()
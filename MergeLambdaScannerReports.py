#!/usr/bin/env python3
"""
MergeLambdaScannerReports.py.py

Merge multiple runs of `lambda-security-scanner` (one run per account/
profile and/or region) into one master triage report.

lambda-security-scanner writes, per run, into whatever --output-dir you
gave it:
    lambda_scan_<region>_<timestamp>.json    <- full results (read by this script)
    lambda_scan_<region>_<timestamp>.csv     <- flat summary (not read - superseded by
                                                 the merged function_inventory.csv below)
    lambda_scan_<region>_<timestamp>.html    <- single-run HTML report
    lambda_compliance_<region>_<timestamp>.json

This script recursively finds every lambda_scan_*.json under --input-dir
(so it doesn't matter how many output folders you used, or what you named
them - one per account is the natural way to run it, but any layout works),
and for each Lambda function keeps only the newest scan (by the file's
summary.scan_time, so re-scanning an account doesn't produce duplicates).

Each scan result already carries a computed "issues" list (severity,
issue_type, description, recommendation) from the scanner's own 21 checks -
this script doesn't re-derive findings, it merges and cross-references the
ones the tool already found across every account/region.

On top of that it builds a short "needs further investigation" roadmap:
functions whose environment variables look secret-shaped (by NAME/type
only - the scanner never captures the actual value, so neither does this
report), functions that are reachable without authentication, and a
cross-account compliance rollup (AWS-FSBP, CIS, PCI-DSS, HIPAA, etc.).

Outputs (written to --output-dir):
  master_report.html          filterable/sortable HTML triage report
  master_report.json          full merged data
  account_summary.csv         one row per account: functions, scores, issues by severity
  priority_findings.csv       one row per (function, issue) - the core findings list
  function_inventory.csv      one row per function - merged version of the tool's own CSV
  secrets_to_investigate.csv  functions with secret-shaped env vars (names/types only)
  public_functions.csv        functions reachable without authentication
  compliance_summary.csv      per-account, per-framework compliance rollup

Usage:
  python3 MergeLambdaScannerReports.py.py -i ./scans -o ./scans/master-report
  python3 MergeLambdaScannerReports.py.py --input-dir . --output-dir ./master-report

Requires: alive-progress (pip install alive-progress)
"""

import argparse
import csv
import glob
import html
import json
import os
import sys
from collections import defaultdict
from datetime import datetime

try:
    from alive_progress import alive_bar
except ImportError:
    sys.exit(
        "error: the 'alive-progress' package is required.\n"
        "Install it with: pip install alive-progress"
    )

SEVERITY_ORDER = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'ERROR': 0}


def discover_scan_files(input_dir):
    pattern = os.path.join(input_dir, '**', 'lambda_scan_*.json')
    return sorted(glob.glob(pattern, recursive=True))


def parse_scan_time(summary, fallback_path):
    t = summary.get('scan_time')
    if t:
        try:
            return datetime.fromisoformat(t)
        except ValueError:
            pass
    try:
        return datetime.fromtimestamp(os.path.getmtime(fallback_path))
    except OSError:
        return datetime.min


def function_key(result):
    arn = (result.get('function_arn') or '').strip()
    if arn:
        return arn
    return (result.get('account_id', ''), result.get('region', ''), result.get('function_name', ''))


def merge_functions(scan_files, on_file=None):
    """Read every lambda_scan_*.json; keep only the newest scan per function.

    on_file, if given, is called once per file *after* it has been read and
    folded into the running merge (so a caller-driven progress bar reflects
    real work, not just a list of filenames).
    """
    best = {}  # key -> (scan_time, result)
    warnings = []
    for path in scan_files:
        try:
            with open(path, encoding='utf-8', errors='replace') as f:
                data = json.load(f)
        except Exception as e:
            warnings.append(f"failed to parse {path}: {e}")
            if on_file:
                on_file(path)
            continue

        summary = data.get('summary') or {}
        results = data.get('results') or []
        scan_time = parse_scan_time(summary, path)

        for result in results:
            result = dict(result)
            result.setdefault('account_id', summary.get('account_id', 'unknown'))
            result.setdefault('region', summary.get('region', 'unknown'))
            result['_source_file'] = path
            key = function_key(result)
            prev = best.get(key)
            if prev is None or scan_time >= prev[0]:
                best[key] = (scan_time, result)

        if on_file:
            on_file(path)

    functions = [v[1] for v in best.values()]
    return functions, warnings


def build_account_summary(functions):
    accounts = defaultdict(lambda: {
        'total_functions': 0, 'scanned_functions': 0, 'scan_errors': 0,
        'scores': [], 'public_functions': 0, 'functions_with_secrets': 0,
        'deprecated_runtime': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0,
        'regions': set(),
    })
    for fn in functions:
        a = accounts[fn.get('account_id', 'unknown')]
        a['total_functions'] += 1
        a['regions'].add(fn.get('region', 'unknown'))
        if fn.get('scan_error'):
            a['scan_errors'] += 1
            continue
        a['scanned_functions'] += 1
        score = fn.get('security_score')
        if score is not None:
            a['scores'].append(score)
        if fn.get('is_public'):
            a['public_functions'] += 1
        if (fn.get('environment_secrets') or {}).get('has_secrets'):
            a['functions_with_secrets'] += 1
        if (fn.get('runtime') or {}).get('status') in ('deprecated', 'blocked'):
            a['deprecated_runtime'] += 1
        for issue in fn.get('issues') or []:
            sev = (issue.get('severity') or '').lower()
            if sev in ('critical', 'high', 'medium', 'low'):
                a[sev] += 1
    return accounts


def build_priority_findings(functions):
    rows = []
    for fn in functions:
        for issue in fn.get('issues') or []:
            rows.append({
                'severity': issue.get('severity', 'UNKNOWN'),
                'account_id': fn.get('account_id', 'unknown'),
                'region': fn.get('region', 'unknown'),
                'function_name': fn.get('function_name', ''),
                'function_arn': fn.get('function_arn', ''),
                'issue_type': issue.get('issue_type', ''),
                'description': issue.get('description', ''),
                'recommendation': issue.get('recommendation', ''),
            })
    rows.sort(key=lambda r: -SEVERITY_ORDER.get(r['severity'], -1))
    return rows


def build_secrets_roadmap(functions):
    """Functions with secret-SHAPED env vars - names/types only, never the value."""
    rows = []
    for fn in functions:
        env = fn.get('environment_secrets') or {}
        if not env.get('has_secrets'):
            continue
        names = env.get('secret_names') or []
        type_by_name = {v.get('name'): v.get('type') for v in (env.get('secret_values') or [])}
        labels = [f"{n} ({type_by_name[n]})" if n in type_by_name else n for n in names]
        rows.append({
            'account_id': fn.get('account_id', 'unknown'), 'region': fn.get('region', 'unknown'),
            'function_name': fn.get('function_name', ''), 'function_arn': fn.get('function_arn', ''),
            'suspect_env_vars': '; '.join(labels), 'has_kms_key': env.get('has_kms_key', False),
        })
    rows.sort(key=lambda r: (r['account_id'], r['function_name']))
    return rows


def build_public_functions(functions):
    rows = []
    for fn in functions:
        if not fn.get('is_public'):
            continue
        rp = fn.get('resource_policy') or {}
        fu = fn.get('function_url') or {}
        reasons = []
        if rp.get('is_public'):
            reasons.append(f"resource policy ({rp.get('public_statement_count', 0)} public statement(s))")
        if fu.get('is_public'):
            reasons.append(f"function URL (auth_type={fu.get('auth_type')})")
        rows.append({
            'account_id': fn.get('account_id', 'unknown'), 'region': fn.get('region', 'unknown'),
            'function_name': fn.get('function_name', ''), 'function_arn': fn.get('function_arn', ''),
            'reason': '; '.join(reasons) or 'unknown', 'function_url': fu.get('function_url') or '',
        })
    rows.sort(key=lambda r: (r['account_id'], r['function_name']))
    return rows


def build_compliance_summary(functions):
    agg = defaultdict(lambda: [0, 0])  # (account_id, framework) -> [compliant, total]
    for fn in functions:
        if fn.get('scan_error'):
            continue
        acct = fn.get('account_id', 'unknown')
        for fw, status in (fn.get('compliance_status') or {}).items():
            agg[(acct, fw)][1] += 1
            if status.get('is_compliant'):
                agg[(acct, fw)][0] += 1
    rows = []
    for (acct, fw), (compliant, total) in sorted(agg.items()):
        rows.append({
            'account_id': acct, 'framework': fw, 'compliant_functions': compliant,
            'total_functions': total,
            'compliance_percentage': round(compliant / total * 100, 1) if total else 0,
        })
    return rows


def build_function_inventory(functions):
    rows = []
    for fn in functions:
        score = fn.get('security_score')
        rows.append({
            'account_id': fn.get('account_id', 'unknown'), 'region': fn.get('region', 'unknown'),
            'function_name': fn.get('function_name', ''), 'function_arn': fn.get('function_arn', ''),
            'runtime': (fn.get('runtime') or {}).get('runtime', 'N/A'),
            'security_score': score, 'issue_count': fn.get('issue_count', 0),
            'has_critical_issues': fn.get('has_critical_issues', False),
            'has_high_issues': fn.get('has_high_issues', False),
            'is_public': fn.get('is_public', False),
            'has_secrets': (fn.get('environment_secrets') or {}).get('has_secrets', False),
            'shared_role': (fn.get('shared_role') or {}).get('is_shared', False),
            'has_admin_execution_role': (fn.get('execution_role') or {}).get('has_admin_access', False),
            'scan_error': fn.get('scan_error', False),
            'source_file': fn.get('_source_file', ''),
        })
    rows.sort(key=lambda r: (r['security_score'] is None, r['security_score'] if r['security_score'] is not None else 0))
    return rows


def write_csv(path, rows, fields):
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        w.writeheader()
        for row in rows:
            w.writerow(row)


HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Lambda Security Scanner Master Report</title>
<style>
  :root {
    --bg: #f7f8fa; --panel: #ffffff; --text: #1b1f24; --muted: #5b6472;
    --border: #dde1e6; --critical: #8f1d1d; --critical-bg: #fbe4e4;
    --high: #c0292a; --high-bg: #fdecec; --medium: #9a6400; --medium-bg: #fdf3dc;
    --low: #3d6b3d; --low-bg: #eaf3ea; --neutral: #5b6472; --neutral-bg: #eceff1; --accent: #2f5fd6;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #14171b; --panel: #1d2126; --text: #e8eaed; --muted: #9aa4af;
      --border: #2c3238; --critical: #ff8a8a; --critical-bg: #3d1414;
      --high: #ff6b6b; --high-bg: #3a1d1d; --medium: #f0b429; --medium-bg: #3a301a;
      --low: #7fbf7f; --low-bg: #1c2b1c; --neutral: #9aa4af; --neutral-bg: #262b30; --accent: #6d9bff;
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
  .badge.critical { background: var(--critical-bg); color: var(--critical); }
  .badge.high { background: var(--high-bg); color: var(--high); }
  .badge.medium { background: var(--medium-bg); color: var(--medium); }
  .badge.low { background: var(--low-bg); color: var(--low); }
  .badge.error { background: var(--neutral-bg); color: var(--neutral); }
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
  <h1>Lambda Security Scanner Master Report</h1>
  <p>Generated __GENERATED_AT__ &middot; __ACCOUNT_COUNT__ account(s), __FUNCTION_COUNT__ function(s) merged from __FILE_COUNT__ scan file(s)</p>
</header>
<main>
  <div class="cards" id="summary-cards"></div>

  <section>
    <h2>Accounts scanned</h2>
    <div class="table-scroll">
    <table id="accounts-table">
      <thead>
        <tr>
          <th data-key="account_id">Account</th>
          <th data-key="regions">Regions</th>
          <th data-key="total_functions">Functions</th>
          <th data-key="avg_score">Avg Score</th>
          <th data-key="public_functions">Public</th>
          <th data-key="functions_with_secrets">Secret-shaped Env Vars</th>
          <th data-key="critical">Critical</th>
          <th data-key="high">High</th>
        </tr>
      </thead>
      <tbody></tbody>
    </table>
    </div>
  </section>

  <section>
    <h2>Priority findings <span class="count-pill" id="findings-count"></span></h2>
    <div class="controls">
      <input type="text" id="search" placeholder="Search function, issue type, description...">
      <select id="severity-filter">
        <option value="">All severities</option>
        <option value="CRITICAL">Critical only</option>
        <option value="HIGH">High only</option>
        <option value="MEDIUM">Medium only</option>
        <option value="LOW">Low only</option>
        <option value="ERROR">Scan errors</option>
      </select>
      <select id="account-filter"><option value="">All accounts</option></select>
    </div>
    <div class="table-scroll">
    <table id="findings-table">
      <thead>
        <tr>
          <th data-key="severity">Severity</th>
          <th data-key="issue_type">Issue Type</th>
          <th data-key="function_name">Function</th>
          <th data-key="description">Description</th>
          <th data-key="recommendation">Recommendation</th>
          <th data-key="account_id">Account</th>
        </tr>
      </thead>
      <tbody></tbody>
    </table>
    </div>
  </section>

  <section>
    <h2>Needs further investigation <span class="muted">(not findings by themselves - what's left to check)</span></h2>
    <p class="roadmap-note">Full detail is in the linked CSV files next to this report, not restated here.</p>
    <div class="table-scroll">
      <table>
        <thead><tr><th>Artifact</th><th>What it is</th><th>Count</th></tr></thead>
        <tbody>
__ROADMAP_ROWS__
        </tbody>
      </table>
    </div>
  </section>
</main>

<script>
const ACCOUNTS = __ACCOUNTS_JSON__;
const FINDINGS = __FINDINGS_JSON__;

function el(tag, attrs, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === 'text') e.textContent = v; else e.setAttribute(k, v);
  }
  children.forEach(c => { if (c !== null && c !== undefined) e.appendChild(c); });
  return e;
}
function badge(sev) { return el('span', { class: 'badge ' + sev.toLowerCase(), text: sev }); }

(function renderCards() {
  const totalFns = ACCOUNTS.reduce((s, a) => s + a.total_functions, 0);
  const critical = ACCOUNTS.reduce((s, a) => s + a.critical, 0);
  const high = ACCOUNTS.reduce((s, a) => s + a.high, 0);
  const publicFns = ACCOUNTS.reduce((s, a) => s + a.public_functions, 0);
  const secretFns = ACCOUNTS.reduce((s, a) => s + a.functions_with_secrets, 0);
  const cards = [
    ['Accounts', ACCOUNTS.length], ['Functions', totalFns],
    ['Critical findings', critical], ['High findings', high],
    ['Public functions', publicFns], ['Secret-shaped env vars', secretFns],
  ];
  const wrap = document.getElementById('summary-cards');
  cards.forEach(([label, num]) => {
    wrap.appendChild(el('div', { class: 'card' }, el('div', { class: 'num', text: num }), el('div', { class: 'label', text: label })));
  });
})();

let accountSort = { key: 'critical', dir: -1 };
function renderAccounts() {
  const tbody = document.querySelector('#accounts-table tbody');
  tbody.innerHTML = '';
  const rows = [...ACCOUNTS].sort((a, b) => {
    const ka = a[accountSort.key], kb = b[accountSort.key];
    if (ka < kb) return -1 * accountSort.dir;
    if (ka > kb) return 1 * accountSort.dir;
    return 0;
  });
  rows.forEach(a => {
    tbody.appendChild(el('tr', {},
      el('td', { text: a.account_id }), el('td', { text: a.regions }),
      el('td', { text: a.total_functions }), el('td', { text: a.avg_score }),
      el('td', { text: a.public_functions }), el('td', { text: a.functions_with_secrets }),
      el('td', {}, badge('critical'), document.createTextNode(' ' + a.critical)),
      el('td', {}, badge('high'), document.createTextNode(' ' + a.high)),
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
const accountNames = [...new Set(FINDINGS.map(f => f.account_id))].sort();
accountNames.forEach(a => document.getElementById('account-filter').appendChild(el('option', { value: a, text: a })));

function renderFindings() {
  const q = document.getElementById('search').value.trim().toLowerCase();
  const severity = document.getElementById('severity-filter').value;
  const account = document.getElementById('account-filter').value;
  let rows = FINDINGS.filter(f => {
    if (severity && f.severity !== severity) return false;
    if (account && f.account_id !== account) return false;
    if (q && !(f.function_name + ' ' + f.issue_type + ' ' + f.description + ' ' + f.account_id).toLowerCase().includes(q)) return false;
    return true;
  });
  rows.sort((a, b) => {
    let ka = findingSort.key === 'severity' ? SEVERITY_ORDER[a.severity] || 0 : a[findingSort.key];
    let kb = findingSort.key === 'severity' ? SEVERITY_ORDER[b.severity] || 0 : b[findingSort.key];
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
      el('td', { text: f.issue_type }),
      el('td', { text: f.function_name }),
      el('td', { text: f.description, class: 'wrap' }),
      el('td', { text: f.recommendation, class: 'wrap' }),
      el('td', { text: f.account_id }),
    ));
  });
}
const SEVERITY_ORDER = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, ERROR: 0 };
document.querySelectorAll('#findings-table th').forEach(th => th.addEventListener('click', () => {
  const key = th.dataset.key;
  findingSort.dir = (findingSort.key === key) ? -findingSort.dir : -1;
  findingSort.key = key;
  renderFindings();
}));
['search', 'severity-filter', 'account-filter'].forEach(id =>
  document.getElementById(id).addEventListener('input', renderFindings));

renderAccounts();
renderFindings();
</script>
</body>
</html>
"""


def render_roadmap_rows(counts):
    descriptions = {
        'secrets_to_investigate.csv': ('Functions with secret-shaped environment variable names/types - '
                                        'go pull the actual value with get-function-configuration and confirm.'),
        'public_functions.csv': ('Functions reachable without authentication (public resource policy or '
                                  'unauthenticated function URL) - worth testing what they expose.'),
        'compliance_summary.csv': 'Per-account, per-framework compliance percentage (AWS-FSBP, CIS, PCI-DSS, HIPAA, ...).',
        'function_inventory.csv': 'Every function merged into one table, worst security score first.',
    }
    rows = []
    for fname, count in counts.items():
        if count == 0:
            continue
        rows.append(
            f'<tr><td><a href="{html.escape(fname)}">{html.escape(fname)}</a></td>'
            f'<td class="wrap">{html.escape(descriptions.get(fname, ""))}</td><td>{count}</td></tr>'
        )
    return '\n'.join(rows) if rows else '<tr><td colspan="3" class="muted">Nothing to report.</td></tr>'


def render_html(account_rows, findings, roadmap_counts, function_count, file_count):
    def dump(obj):
        return json.dumps(obj).replace('</', '<\\/')

    out = HTML_TEMPLATE
    out = out.replace('__GENERATED_AT__', html.escape(datetime.now().strftime('%Y-%m-%d %H:%M')))
    out = out.replace('__ACCOUNT_COUNT__', str(len(account_rows)))
    out = out.replace('__FUNCTION_COUNT__', str(function_count))
    out = out.replace('__FILE_COUNT__', str(file_count))
    out = out.replace('__ACCOUNTS_JSON__', dump(account_rows))
    out = out.replace('__FINDINGS_JSON__', dump(findings))
    out = out.replace('__ROADMAP_ROWS__', render_roadmap_rows(roadmap_counts))
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-i', '--input-dir', default='.',
                         help='Folder to search (recursively) for lambda_scan_*.json files (default: current directory)')
    parser.add_argument('-o', '--output-dir', default='./lambda-scanner-master-report',
                         help='Folder to write the merged report into (default: ./lambda-scanner-master-report)')
    args = parser.parse_args()

    input_dir = os.path.abspath(os.path.expanduser(args.input_dir))
    if not os.path.isdir(input_dir):
        print(f"error: not a directory: {input_dir}", file=sys.stderr)
        sys.exit(1)

    output_dir = os.path.abspath(os.path.expanduser(args.output_dir))
    os.makedirs(output_dir, exist_ok=True)

    scan_files = discover_scan_files(input_dir)
    if not scan_files:
        print(f"error: no lambda_scan_*.json files found under {input_dir}", file=sys.stderr)
        sys.exit(1)

    with alive_bar(len(scan_files), title='Reading scan results') as bar:
        def _tick(path):
            bar.text = f'-> {os.path.relpath(path, input_dir)}'
            bar()
        functions, warnings = merge_functions(scan_files, on_file=_tick)

    for w in warnings:
        print('warning: ' + w, file=sys.stderr)
    if not functions:
        print("error: no function results found in any scan file", file=sys.stderr)
        sys.exit(1)

    outputs = {}

    def _account_summary():
        accounts = build_account_summary(functions)
        rows = []
        for acct, a in sorted(accounts.items()):
            avg_score = round(sum(a['scores']) / len(a['scores']), 1) if a['scores'] else None
            rows.append({
                'account_id': acct, 'regions': ', '.join(sorted(a['regions'])),
                'total_functions': a['total_functions'], 'scanned_functions': a['scanned_functions'],
                'scan_errors': a['scan_errors'], 'avg_score': avg_score,
                'public_functions': a['public_functions'], 'functions_with_secrets': a['functions_with_secrets'],
                'deprecated_runtime': a['deprecated_runtime'],
                'critical': a['critical'], 'high': a['high'], 'medium': a['medium'], 'low': a['low'],
            })
        write_csv(os.path.join(output_dir, 'account_summary.csv'), rows,
                  ['account_id', 'regions', 'total_functions', 'scanned_functions', 'scan_errors', 'avg_score',
                   'public_functions', 'functions_with_secrets', 'deprecated_runtime', 'critical', 'high', 'medium', 'low'])
        outputs['account_rows'] = rows

    def _priority_findings():
        rows = build_priority_findings(functions)
        write_csv(os.path.join(output_dir, 'priority_findings.csv'), rows,
                  ['severity', 'account_id', 'region', 'function_name', 'function_arn',
                   'issue_type', 'description', 'recommendation'])
        outputs['findings'] = rows

    def _function_inventory():
        rows = build_function_inventory(functions)
        write_csv(os.path.join(output_dir, 'function_inventory.csv'), rows,
                  ['account_id', 'region', 'function_name', 'function_arn', 'runtime', 'security_score',
                   'issue_count', 'has_critical_issues', 'has_high_issues', 'is_public', 'has_secrets',
                   'shared_role', 'has_admin_execution_role', 'scan_error', 'source_file'])
        outputs['roadmap_counts'] = outputs.get('roadmap_counts', {})
        outputs['roadmap_counts']['function_inventory.csv'] = len(rows)

    def _secrets_roadmap():
        rows = build_secrets_roadmap(functions)
        write_csv(os.path.join(output_dir, 'secrets_to_investigate.csv'), rows,
                  ['account_id', 'region', 'function_name', 'function_arn', 'suspect_env_vars', 'has_kms_key'])
        outputs['roadmap_counts'] = outputs.get('roadmap_counts', {})
        outputs['roadmap_counts']['secrets_to_investigate.csv'] = len(rows)

    def _public_roadmap():
        rows = build_public_functions(functions)
        write_csv(os.path.join(output_dir, 'public_functions.csv'), rows,
                  ['account_id', 'region', 'function_name', 'function_arn', 'reason', 'function_url'])
        outputs['roadmap_counts'] = outputs.get('roadmap_counts', {})
        outputs['roadmap_counts']['public_functions.csv'] = len(rows)

    def _compliance_summary():
        rows = build_compliance_summary(functions)
        write_csv(os.path.join(output_dir, 'compliance_summary.csv'), rows,
                  ['account_id', 'framework', 'compliant_functions', 'total_functions', 'compliance_percentage'])
        outputs['roadmap_counts'] = outputs.get('roadmap_counts', {})
        outputs['roadmap_counts']['compliance_summary.csv'] = len(rows)

    def _write_json():
        with open(os.path.join(output_dir, 'master_report.json'), 'w', encoding='utf-8') as f:
            json.dump({
                'accounts': outputs['account_rows'], 'findings': outputs['findings'], 'functions': functions,
            }, f, indent=2, default=str)

    def _write_html():
        account_rows = []
        for a in outputs['account_rows']:
            account_rows.append({**a, 'avg_score': a['avg_score'] if a['avg_score'] is not None else 0})
        findings_json = [{
            'severity': f['severity'], 'issue_type': f['issue_type'], 'function_name': f['function_name'],
            'description': f['description'], 'recommendation': f['recommendation'], 'account_id': f['account_id'],
        } for f in outputs['findings']]
        with open(os.path.join(output_dir, 'master_report.html'), 'w', encoding='utf-8') as f:
            f.write(render_html(account_rows, findings_json, outputs['roadmap_counts'],
                                 len(functions), len(scan_files)))

    steps = [
        ('writing account_summary.csv', _account_summary),
        ('writing priority_findings.csv', _priority_findings),
        ('writing function_inventory.csv', _function_inventory),
        ('writing secrets_to_investigate.csv', _secrets_roadmap),
        ('writing public_functions.csv', _public_roadmap),
        ('writing compliance_summary.csv', _compliance_summary),
        ('writing master_report.json', _write_json),
        ('writing master_report.html', _write_html),
    ]
    with alive_bar(len(steps), title='Generating merged report') as bar:
        for label, step in steps:
            bar.text = f'-> {label}'
            step()
            bar()

    total_critical = sum(a['critical'] for a in outputs['account_rows'])
    total_high = sum(a['high'] for a in outputs['account_rows'])
    print(f"Merged {len(scan_files)} scan file(s) into {len(functions)} function(s) across "
          f"{len(outputs['account_rows'])} account(s): {total_critical} critical / {total_high} high findings.")
    print(f"Output written to: {output_dir}")
    for fname in ('master_report.html', 'master_report.json', 'account_summary.csv', 'priority_findings.csv',
                  'function_inventory.csv', 'secrets_to_investigate.csv', 'public_functions.csv',
                  'compliance_summary.csv'):
        print(f"  - {os.path.join(output_dir, fname)}")


if __name__ == '__main__':
    main()
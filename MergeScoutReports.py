#!/usr/bin/env python3
"""
MergeScoutReports.py.py

Merge multiple per-account ScoutSuite AWS reports into one master report.

Expects a parent directory containing one subfolder per account/profile,
matching the layout produced by ScoutSuite's --report-dir option, e.g.:

    scoutsuite-reports/
      account-one/
        scoutsuite-results/scoutsuite_results_aws-account-one.js
        ...
      account-two/
        scoutsuite-results/scoutsuite_results_aws-account-two.js
        ...

Each subfolder is searched recursively for a scoutsuite_results_*.js file,
so it doesn't matter whether ScoutSuite nested its output under an extra
"scoutsuite-report" directory or wrote directly into the folder you gave it.

Outputs (written to --output, default "<parent_dir>/master-report"):
  master_report.json   full aggregated data (per-account + cross-account)
  account_summary.csv  one row per account with totals
  findings_detail.csv  one row per (account, flagged finding)
  master_report.html   single-file, filterable/sortable HTML report

Usage:
  python3 MergeScoutReports.py.py ./scoutsuite-reports
  python3 MergeScoutReports.py.py ./scoutsuite-reports -o ./master-report
  python3 MergeScoutReports.py.py ./scoutsuite-reports --include-clean

Requires: alive-progress (pip install alive-progress) for the progress bars.
"""

import argparse
import csv
import glob
import html
import json
import os
import sys

try:
    from alive_progress import alive_bar
except ImportError:
    sys.exit(
        "error: the 'alive-progress' package is required.\n"
        "Install it with: pip install alive-progress"
    )


def find_results_file(account_dir):
    """Locate scoutsuite_results_*.js anywhere under an account's report folder."""
    pattern = os.path.join(account_dir, '**', 'scoutsuite_results_*.js')
    matches = sorted(glob.glob(pattern, recursive=True), key=os.path.getmtime, reverse=True)
    if not matches:
        return None, []
    return matches[0], matches[1:]


def load_results(js_path):
    """Parse a ScoutSuite scoutsuite_results_*.js file (JS variable assignment) into a dict."""
    with open(js_path, encoding='utf-8', errors='replace') as f:
        text = f.read()
    start = text.find('{')
    if start == -1:
        raise ValueError(f'no JSON payload found in {js_path}')
    return json.loads(text[start:])


def collect_account(account_dir, include_clean):
    name = os.path.basename(account_dir.rstrip(os.sep)) or account_dir
    warnings = []

    js_path, extras = find_results_file(account_dir)
    if not js_path:
        warnings.append(f"[{name}] no scoutsuite_results_*.js found under {account_dir} - skipped")
        return None, warnings

    if extras:
        warnings.append(
            f"[{name}] found {len(extras) + 1} result files; using most recently modified: "
            f"{os.path.relpath(js_path, account_dir)}"
        )

    try:
        data = load_results(js_path)
    except Exception as e:
        warnings.append(f"[{name}] failed to parse {js_path}: {e}")
        return None, warnings

    last_run = data.get('last_run') or {}
    summary = last_run.get('summary') or {}
    services = data.get('services') or {}

    totals = {
        'checked_items': 0,
        'flagged_items': 0,
        'resources_count': 0,
        'rules_flagged_danger': 0,
        'rules_flagged_warning': 0,
        'rules_checked': 0,
    }
    findings = []

    for service_name, service_data in services.items():
        if not isinstance(service_data, dict):
            continue
        service_findings = service_data.get('findings') or {}
        for rule_key, finding in service_findings.items():
            if not isinstance(finding, dict):
                continue
            checked = finding.get('checked_items', 0) or 0
            flagged = finding.get('flagged_items', 0) or 0
            level = finding.get('level', 'warning')

            totals['checked_items'] += checked
            totals['flagged_items'] += flagged
            totals['rules_checked'] += 1
            if flagged > 0:
                if level == 'danger':
                    totals['rules_flagged_danger'] += 1
                else:
                    totals['rules_flagged_warning'] += 1

            if flagged > 0 or include_clean:
                findings.append({
                    'service': service_name,
                    'rule': rule_key,
                    'description': finding.get('description', rule_key),
                    'rationale': finding.get('rationale', ''),
                    'remediation': finding.get('remediation', ''),
                    'level': level,
                    'checked_items': checked,
                    'flagged_items': flagged,
                    'items': finding.get('items', []) or [],
                })

    for svc_summary in summary.values():
        if isinstance(svc_summary, dict):
            totals['resources_count'] += svc_summary.get('resources_count', 0) or 0

    account = {
        'folder': name,
        'account_id': data.get('account_id', 'unknown'),
        'provider': data.get('provider_code', 'aws'),
        'partition': data.get('partition', ''),
        'ruleset_name': last_run.get('ruleset_name', ''),
        'scan_time': last_run.get('time', ''),
        'scout_version': last_run.get('version', ''),
        'totals': totals,
        'findings': sorted(findings, key=lambda f: (-{'danger': 2, 'warning': 1}.get(f['level'], 0), -f['flagged_items'])),
    }
    return account, warnings


def build_rule_index(accounts):
    """Cross-account index: one entry per unique (service, rule), listing which accounts hit it."""
    index = {}
    for acct in accounts:
        for f in acct['findings']:
            key = f"{f['service']}::{f['rule']}"
            entry = index.setdefault(key, {
                'service': f['service'],
                'rule': f['rule'],
                'description': f['description'],
                'rationale': f['rationale'],
                'remediation': f['remediation'],
                'level': f['level'],
                'accounts': {},
                'total_flagged_items': 0,
            })
            if f['level'] == 'danger':
                entry['level'] = 'danger'
            entry['accounts'][acct['folder']] = {
                'flagged_items': f['flagged_items'],
                'checked_items': f['checked_items'],
            }
            entry['total_flagged_items'] += f['flagged_items']
    return index


def write_account_summary_csv(path, accounts):
    fields = ['folder', 'account_id', 'provider', 'ruleset_name', 'scan_time',
              'checked_items', 'flagged_items', 'rules_flagged_danger',
              'rules_flagged_warning', 'resources_count']
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(fields)
        for a in accounts:
            t = a['totals']
            w.writerow([a['folder'], a['account_id'], a['provider'], a['ruleset_name'], a['scan_time'],
                        t['checked_items'], t['flagged_items'], t['rules_flagged_danger'],
                        t['rules_flagged_warning'], t['resources_count']])


def write_findings_detail_csv(path, accounts):
    fields = ['account_folder', 'account_id', 'service', 'rule', 'level',
              'checked_items', 'flagged_items', 'description']
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(fields)
        for a in accounts:
            for finding in a['findings']:
                w.writerow([a['folder'], a['account_id'], finding['service'], finding['rule'],
                            finding['level'], finding['checked_items'], finding['flagged_items'],
                            finding['description']])


HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ScoutSuite Master Report</title>
<style>
  :root {
    --bg: #f7f8fa; --panel: #ffffff; --text: #1b1f24; --muted: #5b6472;
    --border: #dde1e6; --danger: #c0292a; --danger-bg: #fdecec;
    --warning: #9a6400; --warning-bg: #fdf3dc; --accent: #2f5fd6;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #14171b; --panel: #1d2126; --text: #e8eaed; --muted: #9aa4af;
      --border: #2c3238; --danger: #ff6b6b; --danger-bg: #3a1d1d;
      --warning: #f0b429; --warning-bg: #3a301a; --accent: #6d9bff;
    }
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--text);
         font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
  header { padding: 24px 32px; border-bottom: 1px solid var(--border); }
  header h1 { margin: 0 0 4px; font-size: 1.4rem; }
  header p { margin: 0; color: var(--muted); font-size: 0.9rem; }
  main { padding: 24px 32px; max-width: 1400px; margin: 0 auto; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-bottom: 28px; }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 14px 16px; }
  .card .num { font-size: 1.6rem; font-weight: 600; }
  .card .label { color: var(--muted); font-size: 0.8rem; }
  section { margin-bottom: 32px; }
  h2 { font-size: 1.1rem; margin: 0 0 12px; }
  table { width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
  th, td { text-align: left; padding: 9px 12px; border-bottom: 1px solid var(--border); font-size: 0.87rem; vertical-align: top; }
  th { cursor: pointer; user-select: none; color: var(--muted); font-weight: 600; white-space: nowrap; }
  th:hover { color: var(--text); }
  tr:last-child td { border-bottom: none; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 0.75rem; font-weight: 600; }
  .badge.danger { background: var(--danger-bg); color: var(--danger); }
  .badge.warning { background: var(--warning-bg); color: var(--warning); }
  .controls { display: flex; gap: 10px; margin-bottom: 12px; flex-wrap: wrap; }
  input[type=text], select { padding: 7px 10px; border: 1px solid var(--border); border-radius: 6px;
         background: var(--panel); color: var(--text); font-size: 0.87rem; }
  input[type=text] { flex: 1; min-width: 200px; }
  .muted { color: var(--muted); }
  .count-pill { font-size: 0.78rem; color: var(--muted); margin-left: 6px; }
  a { color: var(--accent); }
  .items-toggle { cursor: pointer; color: var(--accent); font-size: 0.8rem; }
  .items-list { margin: 6px 0 0; padding-left: 18px; max-height: 160px; overflow: auto; font-size: 0.8rem; color: var(--muted); }
</style>
</head>
<body>
<header>
  <h1>ScoutSuite Master Report</h1>
  <p>Generated __GENERATED_AT__ &middot; __ACCOUNT_COUNT__ account(s) merged</p>
</header>
<main>
  <div class="cards" id="summary-cards"></div>

  <section>
    <h2>Accounts scanned</h2>
    <table id="accounts-table">
      <thead>
        <tr>
          <th data-key="folder">Account / Profile</th>
          <th data-key="account_id">AWS Account ID</th>
          <th data-key="ruleset_name">Ruleset</th>
          <th data-key="scan_time">Scan Time</th>
          <th data-key="checked_items">Checked</th>
          <th data-key="flagged_items">Flagged</th>
          <th data-key="rules_flagged_danger">Danger Rules</th>
          <th data-key="rules_flagged_warning">Warning Rules</th>
        </tr>
      </thead>
      <tbody></tbody>
    </table>
  </section>

  <section>
    <h2>Findings across all accounts <span class="count-pill" id="findings-count"></span></h2>
    <div class="controls">
      <input type="text" id="search" placeholder="Search rule, service, description...">
      <select id="level-filter">
        <option value="">All levels</option>
        <option value="danger">Danger only</option>
        <option value="warning">Warning only</option>
      </select>
      <select id="service-filter"><option value="">All services</option></select>
      <select id="account-filter"><option value="">All accounts</option></select>
    </div>
    <table id="findings-table">
      <thead>
        <tr>
          <th data-key="level">Level</th>
          <th data-key="service">Service</th>
          <th data-key="rule">Rule</th>
          <th data-key="description">Description</th>
          <th data-key="account">Account</th>
          <th data-key="flagged_items">Flagged</th>
          <th data-key="checked_items">Checked</th>
        </tr>
      </thead>
      <tbody></tbody>
    </table>
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
  children.forEach(c => { if (c) e.appendChild(c); });
  return e;
}

function badge(level) {
  return el('span', { class: 'badge ' + (level === 'danger' ? 'danger' : 'warning'), text: level });
}

// --- summary cards ---
(function renderCards() {
  const totalFlagged = ACCOUNTS.reduce((s, a) => s + a.totals.flagged_items, 0);
  const totalDanger = ACCOUNTS.reduce((s, a) => s + a.totals.rules_flagged_danger, 0);
  const totalWarning = ACCOUNTS.reduce((s, a) => s + a.totals.rules_flagged_warning, 0);
  const cards = [
    ['Accounts', ACCOUNTS.length],
    ['Total flagged items', totalFlagged],
    ['Danger-level rules flagged', totalDanger],
    ['Warning-level rules flagged', totalWarning],
  ];
  const wrap = document.getElementById('summary-cards');
  cards.forEach(([label, num]) => {
    wrap.appendChild(el('div', { class: 'card' },
      el('div', { class: 'num', text: num }),
      el('div', { class: 'label', text: label })));
  });
})();

// --- accounts table ---
let accountSort = { key: 'flagged_items', dir: -1 };
function renderAccounts() {
  const tbody = document.querySelector('#accounts-table tbody');
  tbody.innerHTML = '';
  const rows = [...ACCOUNTS].sort((a, b) => {
    const ka = accountSort.key in a.totals ? a.totals[accountSort.key] : a[accountSort.key];
    const kb = accountSort.key in b.totals ? b.totals[accountSort.key] : b[accountSort.key];
    if (ka < kb) return -1 * accountSort.dir;
    if (ka > kb) return 1 * accountSort.dir;
    return 0;
  });
  rows.forEach(a => {
    tbody.appendChild(el('tr', {},
      el('td', { text: a.folder }),
      el('td', { text: a.account_id }),
      el('td', { text: a.ruleset_name }),
      el('td', { text: a.scan_time }),
      el('td', { text: a.totals.checked_items }),
      el('td', { text: a.totals.flagged_items }),
      el('td', { text: a.totals.rules_flagged_danger }),
      el('td', { text: a.totals.rules_flagged_warning }),
    ));
  });
}
document.querySelectorAll('#accounts-table th').forEach(th => {
  th.addEventListener('click', () => {
    const key = th.dataset.key;
    accountSort.dir = (accountSort.key === key) ? -accountSort.dir : -1;
    accountSort.key = key;
    renderAccounts();
  });
});

// --- findings table ---
let findingSort = { key: 'flagged_items', dir: -1 };
const services = [...new Set(FINDINGS.map(f => f.service))].sort();
const accountNames = [...new Set(FINDINGS.map(f => f.account))].sort();
services.forEach(s => document.getElementById('service-filter').appendChild(el('option', { value: s, text: s })));
accountNames.forEach(a => document.getElementById('account-filter').appendChild(el('option', { value: a, text: a })));

function currentFilters() {
  return {
    q: document.getElementById('search').value.trim().toLowerCase(),
    level: document.getElementById('level-filter').value,
    service: document.getElementById('service-filter').value,
    account: document.getElementById('account-filter').value,
  };
}

function renderFindings() {
  const { q, level, service, account } = currentFilters();
  let rows = FINDINGS.filter(f => {
    if (level && f.level !== level) return false;
    if (service && f.service !== service) return false;
    if (account && f.account !== account) return false;
    if (q && !(f.rule + ' ' + f.service + ' ' + f.description + ' ' + f.account).toLowerCase().includes(q)) return false;
    return true;
  });
  rows.sort((a, b) => {
    const ka = a[findingSort.key], kb = b[findingSort.key];
    if (ka < kb) return -1 * findingSort.dir;
    if (ka > kb) return 1 * findingSort.dir;
    return 0;
  });
  document.getElementById('findings-count').textContent = rows.length + ' of ' + FINDINGS.length;

  const tbody = document.querySelector('#findings-table tbody');
  tbody.innerHTML = '';
  rows.forEach(f => {
    const descCell = el('td', {}, el('div', { text: f.description }));
    if (f.items && f.items.length) {
      const toggle = el('span', { class: 'items-toggle', text: `show ${f.items.length} flagged item(s)` });
      const list = el('ul', { class: 'items-list', style: 'display:none' });
      f.items.slice(0, 200).forEach(it => list.appendChild(el('li', { text: it })));
      toggle.addEventListener('click', () => {
        const showing = list.style.display !== 'none';
        list.style.display = showing ? 'none' : 'block';
        toggle.textContent = showing ? `show ${f.items.length} flagged item(s)` : 'hide flagged items';
      });
      descCell.appendChild(toggle);
      descCell.appendChild(list);
    }
    tbody.appendChild(el('tr', {},
      el('td', {}, badge(f.level)),
      el('td', { text: f.service }),
      el('td', { text: f.rule }),
      descCell,
      el('td', { text: f.account }),
      el('td', { text: f.flagged_items }),
      el('td', { text: f.checked_items }),
    ));
  });
}
document.querySelectorAll('#findings-table th').forEach(th => {
  th.addEventListener('click', () => {
    const key = th.dataset.key;
    findingSort.dir = (findingSort.key === key) ? -findingSort.dir : -1;
    findingSort.key = key;
    renderFindings();
  });
});
['search', 'level-filter', 'service-filter', 'account-filter'].forEach(id =>
  document.getElementById(id).addEventListener('input', renderFindings));

renderAccounts();
renderFindings();
</script>
</body>
</html>
"""


def render_html(accounts, rule_index):
    flat_findings = []
    for a in accounts:
        for f in a['findings']:
            flat_findings.append({
                'account': a['folder'],
                'service': f['service'],
                'rule': f['rule'],
                'description': f['description'],
                'level': f['level'],
                'checked_items': f['checked_items'],
                'flagged_items': f['flagged_items'],
                'items': f['items'][:200],  # cap embedded detail to keep file size sane
            })

    accounts_json = json.dumps(
        [{'folder': a['folder'], 'account_id': a['account_id'], 'ruleset_name': a['ruleset_name'],
          'scan_time': a['scan_time'], 'totals': a['totals']} for a in accounts]
    ).replace('</', '<\\/')
    findings_json = json.dumps(flat_findings).replace('</', '<\\/')

    out = HTML_TEMPLATE
    out = out.replace('__GENERATED_AT__', html.escape(__import__('time').strftime('%Y-%m-%d %H:%M %Z')))
    out = out.replace('__ACCOUNT_COUNT__', str(len(accounts)))
    out = out.replace('__ACCOUNTS_JSON__', accounts_json)
    out = out.replace('__FINDINGS_JSON__', findings_json)
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('reports_dir', help='Parent folder containing one subfolder per ScoutSuite account report')
    parser.add_argument('-o', '--output', default=None,
                         help='Output folder (default: <reports_dir>/master-report)')
    parser.add_argument('--include-clean', action='store_true',
                         help='Include rules with zero flagged items too (default: only flagged findings)')
    args = parser.parse_args()

    reports_dir = os.path.abspath(args.reports_dir)
    if not os.path.isdir(reports_dir):
        print(f"error: not a directory: {reports_dir}", file=sys.stderr)
        sys.exit(1)

    output_dir = os.path.abspath(args.output) if args.output else os.path.join(reports_dir, 'master-report')
    os.makedirs(output_dir, exist_ok=True)

    subdirs = sorted(
        os.path.join(reports_dir, d) for d in os.listdir(reports_dir)
        if os.path.isdir(os.path.join(reports_dir, d)) and d != os.path.basename(output_dir)
    )
    if not subdirs:
        print(f"error: no subfolders found under {reports_dir}", file=sys.stderr)
        sys.exit(1)

    accounts = []
    all_warnings = []
    with alive_bar(len(subdirs), title='Analyzing account reports') as bar:
        for d in subdirs:
            account_name = os.path.basename(d.rstrip(os.sep)) or d
            bar.text = f'-> parsing {account_name}'
            account, warnings = collect_account(d, args.include_clean)
            all_warnings.extend(warnings)
            if account:
                accounts.append(account)
            bar()

    for w in all_warnings:
        print('warning: ' + w, file=sys.stderr)

    if not accounts:
        print("error: no valid ScoutSuite results found in any subfolder", file=sys.stderr)
        sys.exit(1)

    rule_index = {}

    def _build_rule_index():
        nonlocal rule_index
        rule_index = build_rule_index(accounts)

    def _write_json():
        master = {'accounts': accounts, 'findings_by_rule': rule_index}
        with open(os.path.join(output_dir, 'master_report.json'), 'w', encoding='utf-8') as f:
            json.dump(master, f, indent=2, sort_keys=True)

    def _write_account_csv():
        write_account_summary_csv(os.path.join(output_dir, 'account_summary.csv'), accounts)

    def _write_findings_csv():
        write_findings_detail_csv(os.path.join(output_dir, 'findings_detail.csv'), accounts)

    def _write_html():
        with open(os.path.join(output_dir, 'master_report.html'), 'w', encoding='utf-8') as f:
            f.write(render_html(accounts, rule_index))

    report_steps = [
        ('cross-referencing findings across accounts', _build_rule_index),
        ('writing master_report.json', _write_json),
        ('writing account_summary.csv', _write_account_csv),
        ('writing findings_detail.csv', _write_findings_csv),
        ('writing master_report.html', _write_html),
    ]
    with alive_bar(len(report_steps), title='Generating master report') as bar:
        for label, step in report_steps:
            bar.text = f'-> {label}'
            step()
            bar()

    total_flagged = sum(a['totals']['flagged_items'] for a in accounts)
    print(f"Merged {len(accounts)} account(s), {total_flagged} total flagged items.")
    print(f"Output written to: {output_dir}")
    print(f"  - {os.path.join(output_dir, 'master_report.html')}")
    print(f"  - {os.path.join(output_dir, 'master_report.json')}")
    print(f"  - {os.path.join(output_dir, 'account_summary.csv')}")
    print(f"  - {os.path.join(output_dir, 'findings_detail.csv')}")


if __name__ == '__main__':
    main()
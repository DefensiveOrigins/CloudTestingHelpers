# Cloud Pentest Helper Scripts

This repository contains a collection of helper scripts to assist with cloud penetration testing tasks. Each script is designed to automate or simplify common actions during cloud pentests. More scripts will be added over time.

## Included Scripts

### Scout-All-Accounts.sh

Runs [ScoutSuite](https://github.com/nccgroup/ScoutSuite) against every AWS credential profile found in your `~/.aws/credentials` file, saving each report in a separate folder named after the profile.

#### Usage

    ./Scount-All-Accounts.sh [output_root_dir]

- `output_root_dir` (optional): Directory where reports will be saved. Defaults to `./scoutsuite-reports`.

#### Requirements

- [ScoutSuite](https://github.com/nccgroup/ScoutSuite) must be installed and available on your `PATH`.
  - Install with: `pip install scoutsuite`
- AWS credentials file at `~/.aws/credentials` (or set `AWS_SHARED_CREDENTIALS_FILE`).

#### What it does

- Detects all AWS profiles in your credentials file.
- Runs ScoutSuite for each profile.
- Saves each report under `output_root_dir/<profile-name>/`.

#### Example
```
./Scount-All-Accounts.sh
or specify a custom output directory
./Scount-All-Accounts.sh /tmp/pentest-reports
```

---

### MergeScoutReports.py

Merges multiple per-account ScoutSuite AWS reports into one master report for cross-account analysis.

#### Usage

    python3 MergeScoutReports.py ./scoutsuite-reports
    python3 MergeScoutReports.py ./scoutsuite-reports -o ./master-report
    python3 MergeScoutReports.py ./scoutsuite-reports --include-clean

- The script expects a parent directory containing one subfolder per account/profile, each with a ScoutSuite report (as produced by `Scout-All-Accounts.sh`).
- The `-o` or `--output` option lets you specify the output directory (default: `<reports_dir>/master-report`).
- The `--include-clean` flag includes rules with zero flagged items in the output.

#### Output

- `master_report.json`: Full aggregated data (per-account and cross-account).
- `account_summary.csv`: One row per account with totals.
- `findings_detail.csv`: One row per (account, flagged finding) - rule-level rollup.
- `findings_items_detail.csv`: One row per (account, flagged finding, flagged resource) - granular resource-level detail.
- `master_report.html`: Single-file, filterable/sortable HTML report.

#### Requirements

- Python 3
- [alive-progress](https://github.com/rsalmei/alive-progress) for progress bars (`pip install alive-progress`)

#### Example

    python3 MergeScoutReports.py ./scoutsuite-reports

---

### MergeCloudfoxReports.py

Summarizes and cross-references multiple per-account [CloudFox](https://github.com/BishopFox/cloudfox) AWS reports (produced by `cloudfox aws --all-profiles`) into a single master triage report and recon roadmap.

#### Usage

    python3 MergeCloudfoxReports.py
    python3 MergeCloudfoxReports.py ~/.cloudfox/cloudfox-output
    python3 MergeCloudfoxReports.py /path/to/cloudfox-output -o ./master-report

- By default, scans `~/.cloudfox/cloudfox-output` for CloudFox output folders.
- The `-o` or `--output` option lets you specify the output directory (default: `<reports_dir>/master-report`).

#### Output

- `master_report.html`: Single-file, filterable/sortable HTML triage report.
- `master_report.json`: Full aggregated data.
- `account_summary.csv`: One row per account (modules run, resources seen, findings by severity).
- `priority_findings.csv`: One row per flagged finding, across all accounts.
- `module_row_counts.csv`: One row per (module, account): how many resources that module found.
- `scan_targets.csv`: Deduplicated IPs/hostnames/URLs to feed a vuln scanner.
- `s3_bucket_inventory.csv`: Every S3 bucket found, with an already_flagged column.
- `lambda_inventory.csv`: Every Lambda function found, with an already_flagged column.
- `ecr_inventory.csv`: Every ECR repo/image found.
- `cloudformation_inventory.csv`: Stacks with Parameters/Outputs worth pulling manually.
- `ec2_userdata_inventory.csv`: Instances with user data present (not the content itself).
- `roadmap/loot/`: CloudFox's own per-account recon commands, merged across accounts.

#### Requirements

- Python 3
- [alive-progress](https://github.com/rsalmei/alive-progress) for progress bars (`pip install alive-progress`)

#### Example

    python3 MergeCloudfoxReports.py
    python3 MergeCloudfoxReports.py ~/.cloudfox/cloudfox-output -o ./master-report

---

### MergeLambdaScannerReports.py

Merges and summarizes multiple per-account LambdaScanner AWS reports into a single master report for easier triage and cross-account analysis.

#### Usage

    python3 MergeLambdaScannerReports.py <input_dir> [-o <output_dir>]

- The script expects a directory containing LambdaScanner JSON reports for each account.
- The `-o` or `--output` option lets you specify the output directory (default: `<input_dir>/master-report`).

#### Output

- `master_report.html`: Single-file, filterable/sortable HTML triage report.
- `master_report.json`: Full aggregated data.
- `account_summary.csv`: One row per account with summary statistics.
- `findings_detail.csv`: One row per flagged finding, across all accounts.

#### Requirements

- Python 3
- [alive-progress](https://github.com/rsalmei/alive-progress) for progress bars (`pip install alive-progress`)

#### Example

    python3 MergeLambdaScannerReports.py ./lambdascanner-reports
    python3 MergeLambdaScannerReports.py ./lambdascanner-reports -o ./master-report

---

## Contributing

Contributions are welcome! Feel free to submit pull requests with additional scripts or improvements.

## License

MIT License


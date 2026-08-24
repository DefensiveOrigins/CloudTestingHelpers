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

``` bash
    ./Scount-All-Accounts.sh
    # or specify a custom output directory
    ./Scount-All-Accounts.sh /tmp/pentest-reports
```
---

### MergeScoutReports.py

Merges multiple per-account ScoutSuite AWS reports into a single master report for easier cross-account analysis.

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
- `findings_detail.csv`: One row per (account, flagged finding).
- `master_report.html`: Single-file, filterable/sortable HTML report.

#### Requirements

- Python 3
- [alive-progress](https://github.com/rsalmei/alive-progress) for progress bars (`pip install alive-progress`)

#### Example

    python3 MergeScoutReports.py ./scoutsuite-reports

---

## Contributing

Contributions are welcome! Feel free to submit pull requests with additional scripts or improvements.

## License

MIT License

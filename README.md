# Cloud Pentest Helper Scripts

This repository contains a collection of helper scripts to assist with cloud penetration testing tasks. Each script is designed to automate or simplify common actions during cloud pentests. More scripts will be added over time.

## Included Scripts

### Scount-All-Accounts.sh

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

    ./Scount-All-Accounts.sh
    # or specify a custom output directory
    ./Scount-All-Accounts.sh /tmp/pentest-reports

## Contributing

Contributions are welcome! Feel free to submit pull requests with additional scripts or improvements.

## License

MIT License

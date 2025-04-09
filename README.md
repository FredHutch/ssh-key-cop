# SSH Key Cop 👮‍♂️

A utility to monitor and enforce SSH key rotation policies.

## Description

SSH Key Cop checks user's authorized_keys files to enforce key rotation policies. It identifies SSH keys that have been in use longer than a specified threshold (e.g. 30 days) and reports violations via email.

## Features

- Scans all user home directories for authorized_keys files
- Tracks SSH key usage with an SQLite database
- Reports keys that exceed the age threshold
- Configurable email notifications for violations
- External configuration file in INI format
- Dry-run mode for testing
- Database dump option to view all tracked keys

## Requirements

- Python 3.12 or higher
- No third-party dependencies (standard library only)

## Installation

Simply clone this repository:

```bash
git clone https://github.com/robert-mcdermott/ssh-key-cop.git
cd ssh-key-cop
```

Make the script executable:

```bash
chmod +x ssh_key_cop.py
```

## Configuration

SSH Key Cop uses an INI configuration file to store settings. A sample configuration file is provided (`ssh_key_cop.ini.sample`). Copy this file to `ssh_key_cop.ini` and edit as needed:

```bash
cp ssh_key_cop.ini.sample ssh_key_cop.ini
```

### Configuration Options

The configuration file contains these sections:

#### [database]
- `path`: Path to the SQLite database file

#### [keys]
- `expiration_days`: Number of days before a key is considered expired

#### [email]
- `to_address`: Email recipient for violation reports
- `from_address`: Email sender address
- `smtp_server`: SMTP server hostname or IP
- `smtp_port`: SMTP server port
- `smtp_username`: Username for SMTP authentication (optional)
- `smtp_password`: Password for SMTP authentication (optional)
- `use_tls`: Whether to use TLS for SMTP connection

## Usage

Run the utility:

```bash
./ssh_key_cop.py
```

Or using `uv run`:

```bash
uv run ssh_key_cop.py
```

### Command-line Options

```
usage: ssh_key_cop.py [-h] [-c CONFIG] [--dry-run] [--dump] [-v]

SSH Key Cop - Monitor SSH key rotation

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        Path to the configuration file
  --dry-run             Run without modifying the database or sending emails
  --dump                Dump the contents of the database and exit
  -v, --verbose         Enable verbose output
```

### Examples

Check for violations and send email reports:

```bash
uv run ssh_key_cop.py
```

Display all tracked keys in the database:

```bash
uv run ssh_key_cop.py --dump
```

Run in dry-run mode (no database changes or emails):

```bash
uv run ssh_key_cop.py --dry-run
```

Use a specific configuration file:

```bash
uv run ssh_key_cop.py --config /path/to/custom/config.ini
```

## Running as a Scheduled Task

To set up as a cron job for regularly monitoring keys, add something like:

```
# Run SSH Key Cop daily at 1 AM
0 1 * * * cd /path/to/ssh-key-cop && uv run ssh_key_cop.py --config /etc/ssh_key_cop.ini
```

## Future Enhancements

- Automatically remove expired keys from authorized_keys files
- Extended reporting and statistics
- Web interface for easy monitoring

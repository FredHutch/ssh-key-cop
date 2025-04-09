# SSH Key Cop 👮‍♂️

A utility to monitor and enforce SSH key rotation policies.

## Description

SSH Key Cop checks user's authorized_keys files to enforce key rotation policies. It identifies SSH keys that have been in use longer than a specified threshold (e.g. 30 days) and logs violations. It can also automatically add expiration dates to SSH keys in the authorized_keys file to enforce key rotation at the SSH level.

## Features

- Scans all user home directories for authorized_keys files
- Tracks SSH key usage with an SQLite database
- Reports keys that exceed the age threshold via logging
- Configurable key rotation policies
- External configuration file in INI format
- Dry-run mode for testing
- Database dump option to view all tracked keys
- Automatic expiration date management for SSH keys
- Enforces key rotation by setting key expiration dates
- Tamper proof, will detect and correct any attempts by the user to remove or change the expiration date.

## Requirements

- Python 3.9 or higher
- No third-party dependencies (standard library only)
- Root or sudo access (required for accessing user home directories)
- Cron (for scheduled execution)

## Installation

1. Clone this repository to a system directory:

```bash
sudo mkdir -p /opt/ssh-key-cop
sudo git clone https://github.com/robert-mcdermott/ssh-key-cop.git /opt/ssh-key-cop
cd /opt/ssh-key-cop
```

2. Make the script executable:

```bash
sudo chmod +x ssh_key_cop.py
```

3. Set up the configuration:

```bash
sudo cp ssh_key_cop.ini.sample /etc/ssh_key_cop.ini
sudo chmod 600 /etc/ssh_key_cop.ini
```

4. Create the database directory:

```bash
sudo mkdir -p /var/lib/ssh-key-cop
sudo chmod 700 /var/lib/ssh-key-cop
```

5. Set up the cron job:

```bash
sudo crontab -e
```

Add the following line to run the script daily at 1 AM:

```
0 1 * * * /opt/ssh-key-cop/ssh_key_cop.py --config /etc/ssh_key_cop.ini
```

## Configuration

SSH Key Cop uses an INI configuration file to store settings. The configuration file should be placed at `/etc/ssh_key_cop.ini` and should be readable only by root.

### Configuration Options

The configuration file contains these sections:

#### [database]
- `path`: Path to the SQLite database file (e.g., `/var/lib/ssh-key-cop/ssh_key_cop.db`)

#### [keys]
- `expiration_days`: Number of days before a key is considered expired
- `enable_expiration_dates`: Whether to add expiration dates to authorized_keys files (true/false)

## Usage

The script is designed to be run as a scheduled task via cron. However, you can also run it manually:

```bash
sudo /opt/ssh-key-cop/ssh_key_cop.py --config /etc/ssh_key_cop.ini
```

### Command-line Options

```
usage: ssh_key_cop.py [-h] [-c CONFIG] [--dry-run] [--dump] [-v]

SSH Key Cop - Monitor SSH key rotation

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        Path to the configuration file
  --dry-run             Run without modifying the database
  --dump                Dump the contents of the database and exit
  -v, --verbose         Enable verbose output
```

### Examples

Iventory keys, set expiration dates, detect/correct tampering:

```bash
sudo /opt/ssh-key-cop/ssh_key_cop.py
```

Display all tracked keys in the database:

```bash
sudo /opt/ssh-key-cop/ssh_key_cop.py --dump
```

Run in dry-run mode (no database changes):

```bash
sudo /opt/ssh-key-cop/ssh_key_cop.py --dry-run
```

## Expiration Date Management

When `enable_expiration_dates` is set to `true` in the configuration, SSH Key Cop will:

1. Add `expiry-time="YYYYMMDDHHMM"` directives to keys in authorized_keys files
2. Calculate expiration dates based on the key's first seen date in the database
3. Validate existing expiration dates against the database
4. Correct expiration dates that don't match the expected date
5. Add expiration dates to keys that don't have them

The expiration date format is `YYYYMMDDHHMM` (e.g., "202504101116" for April 10, 2025, 11:16 AM).

## Logging

SSH Key Cop supports two logging destinations:

1. Console (stdout) - Always enabled
2. File - Optional, configured in the config file

### Logging Configuration

The logging section in the configuration file supports this option:

#### [logging]
- `file`: Path to log file (e.g., `/var/log/ssh-key-cop.log`)

Example configuration:
```ini
[logging]
file = /var/log/ssh-key-cop.log
```

### Log File Rotation

When using file logging, logs are automatically rotated:
- Maximum file size: 10MB
- Number of backup files: 5
- Backup files are named with .1, .2, etc. suffixes

### Log Levels

- INFO: Normal operation messages
- WARNING: Key violations and potential issues
- ERROR: Critical errors that need attention
- DEBUG: Detailed information (enabled with --verbose flag)

Example log entries:
```
WARNING: Found 2 key violations
WARNING: Key violation: user1's key is 45 days old (first seen: 2024-02-01T12:00:00)
WARNING: Key violation: user2's key is 60 days old (first seen: 2024-01-15T08:30:00)
```

### Viewing Logs

Depending on your configuration, logs can be viewed in different ways:

1. Console output (always available)
2. Log file (if configured):
   ```bash
   sudo tail -f /var/log/ssh-key-cop.log
   ```

## Security Considerations

1. The script needs to access and modify files located in user's home directories, this means it will need to run with `root` or `sudo` rights for function correctly.
2. The script and its configuration files should be owned by root and not writable by other users
3. The database file should be readable only by root
4. Consider using SELinux or AppArmor to restrict the script's access to only necessary directories
5. Monitor the logs for any unauthorized access attempts
6. Regular security audits should be performed on the script and its configuration



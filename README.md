# SSH Key Cop 👮‍♂️

A utility to monitor and enforce SSH key rotation policies.

## Description

SSH Key Cop checks user's authorized_keys files to enforce key rotation policies. It identifies SSH keys that have been in use longer than a specified threshold (e.g. 30 days) and logs violations. It can also automatically add expiration dates to SSH keys in the authorized_keys file to enforce key rotation at the SSH level, and send email notifications when keys are about to expire or have expired.

## Features

- Scans all user home directories for authorized_keys files
- Tracks SSH key usage with an SQLite database
- Reports keys that exceed the age threshold via logging
- External configuration file in INI format
- Dry-run mode for testing
- Database dump option to view all tracked keys
- Automatic expiration date management for SSH keys
- Enforces key rotation by setting key expiration dates
- Tamper proof, will detect and correct any attempts by the user to remove or change the expiration date
- Email notifications for soon-to-expire and expired keys
- Customizable email templates

## Requirements

- Python 3.9 or higher
- No third-party dependencies (standard library only)
- Root or sudo access (required for accessing user home directories)
- Cron (for scheduled execution)

## Installation

1. Clone this repository to a system directory:

```bash
sudo mkdir -p /opt/ssh-key-cop
sudo git clone https://github.com/fredhutch/ssh-key-cop.git /opt/ssh-key-cop
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

#### [email]
- `enable_notifications`: Whether to enable email notifications (true/false)
- `notification_days_before`: Number of days before expiration to send warning notification
- `template_path`: Path to the email template file
- `notify_admin`: Whether to send copies of all notifications to the admin email address (true/false)
- `to_address`: Administrator email address for notifications
- `from_address`: Sender email address for notifications
- `smtp_server`: SMTP server hostname
- `smtp_port`: SMTP server port
- `smtp_username`: SMTP authentication username (optional)
- `smtp_password`: SMTP authentication password (optional)
- `use_tls`: Whether to use TLS for SMTP connections (true/false)
- `default_domain`: Default domain for user email addresses (defaults to fredhutch.org)

#### [user_emails]
- Custom mappings for user email addresses in the format: `username = email@example.com`
- If not specified, user emails are constructed as `username@default_domain`

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

## Security Considerations

1. The script needs to access and modify files located in user's home directories, this means it will need to run with `root` or `sudo` rights for function correctly.
2. The script and its configuration files should be owned by root and not writable by other users
3. The database file should be readable only by root

## Email Notifications

When `enable_notifications` is set to `true` in the configuration, SSH Key Cop will:

1. Send warning emails to users when their keys are about to expire (within the `notification_days_before` threshold)
2. Send notifications when keys have expired
3. Track sent notifications to avoid duplicate emails
4. Use customizable email templates

### Email Templates

Email templates are defined in a separate file (specified by `template_path` in the config) and have two sections:

```
---- WARNING TEMPLATE ----
Subject: SSH Key Expiration Warning

Dear {username},

This is an automated notification from SSH Key Cop.

Your SSH key (signature: {key_signature}) on the SSH gateway server will expire in {days_remaining} days, on {expiration_date}.

To prevent access issues, please rotate your key before it expires by:
1. Generating a new SSH key pair
2. Adding the new public key to your ~/.ssh/authorized_keys file
3. Testing the connection with your new key

If you need assistance, please contact the system administrator.

Thank you for helping maintain our security standards.

---- EXPIRED TEMPLATE ----
Subject: SSH Key Has Expired

Dear {username},

This is an automated notification from SSH Key Cop.

Your SSH key (signature: {key_signature}) on the SSH gateway server expired on {expiration_date} ({days_expired} days ago).

To regain access, please:
1. Generate a new SSH key pair
2. Add the new public key to your ~/.ssh/authorized_keys file
3. Test the connection with your new key

If you need assistance, please contact the system administrator.

Note: Your expired key will be automatically removed from the system within 48 hours.
```

Available template variables:
- `{username}`: The user's username
- `{key_signature}`: The SSH key signature
- `{expiration_date}`: The key's expiration date (format: YYYY-MM-DD)
- `{days_remaining}`: Days remaining until expiration (for warning template)
- `{days_expired}`: Days since expiration (for expired template)

### Email Addressing

SSH Key Cop determines user email addresses as follows:

1. Check for a specific override in the `[user_emails]` section
2. If no override exists, combine the username with the `default_domain` from the config
3. Default domain is "fredhutch.org" if not specified


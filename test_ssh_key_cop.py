#!/usr/bin/env python3
"""
Test script for SSH Key Cop.

This script creates a temporary test environment to demonstrate SSH Key Cop functionality.
It simulates user home directories with authorized_keys files.
"""

import argparse
import configparser
import datetime
import os
import sqlite3
import shutil
import sys
import tempfile
from pathlib import Path
import subprocess
import importlib.util
import re

# Sample authorized_keys entries for testing
SAMPLE_KEYS = [
    # Current key (less than 30 days old)
    "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEA6vRl3UcgQmEoPJB4MHWYaf+9fiGwSABQDh4tYGKYP+31w9Sj5BU8EyoReFF3+P5+7dFy+jtLG8j6ZHCWMS4ugtZsZE3R0AuIYUHifOH3KQEvxWNmRNR6yYfVSPNNkIoDIwfWcbfHsxpHcD2Fjf5jygirGkkh0/KHHrVdAyER10k= test-user1@example.com",
    
    # Older key (more than 30 days old)
    "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEAn3BWdpK5zX/8MVx724esiTXR49QzLdy5u5AoKTGFL7gbpH5NxTARHRSlv//U1+0V430tLJbecs8G7KKtg18U6FMsWls+lbg2weuzS8MpTgM2TXk33dKOQfgjq1ay71HvPLIOJ2nTac3TNJFqEThLtTuoCArDKo08qoWNu9P18hk= test-user2@example.com",
    
    # Another current key
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBTZSt5IZWZaGEJt8l5CI4DijXPr78L7HHEfB3SJlzFZ test-user3@example.com"
]

# Sample keys with expiration dates
SAMPLE_KEYS_WITH_EXPIRATION = [
    # Key with correct expiration date
    "expiry-time=202403151200 ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEA6vRl3UcgQmEoPJB4MHWYaf+9fiGwSABQDh4tYGKYP+31w9Sj5BU8EyoReFF3+P5+7dFy+jtLG8j6ZHCWMS4ugtZsZE3R0AuIYUHifOH3KQEvxWNmRNR6yYfVSPNNkIoDIwfWcbfHsxpHcD2Fjf5jygirGkkh0/KHHrVdAyER10k= test-user1@example.com",
    
    # Key with incorrect expiration date
    "expiry-time=202403151200 ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEAn3BWdpK5zX/8MVx724esiTXR49QzLdy5u5AoKTGFL7gbpH5NxTARHRSlv//U1+0V430tLJbecs8G7KKtg18U6FMsWls+lbg2weuzS8MpTgM2TXk33dKOQfgjq1ay71HvPLIOJ2nTac3TNJFqEThLtTuoCArDKo08qoWNu9P18hk= test-user2@example.com",
    
    # Key without expiration date
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBTZSt5IZWZaGEJt8l5CI4DijXPr78L7HHEfB3SJlzFZ test-user3@example.com"
]


def create_test_config(test_home, db_path, enable_expiration=False, enable_email=False):
    """Create a test configuration file."""
    config_path = os.path.join(test_home, "test_config.ini")
    config = configparser.ConfigParser()
    
    config['database'] = {
        'path': db_path
    }
    
    config['keys'] = {
        'expiration_days': '30',
        'enable_expiration_dates': str(enable_expiration).lower()
    }
    
    # Add email section if enabled
    if enable_email:
        template_path = os.path.join(test_home, "email_template.txt")
        
        # Create a simple email template file
        with open(template_path, 'w') as f:
            f.write("""---- WARNING TEMPLATE ----
Subject: Test Warning

Your key will expire in {days_remaining} days (on {expiration_date}).

---- EXPIRED TEMPLATE ----
Subject: Test Expired

Your key expired on {expiration_date} ({days_expired} days ago).
""")
            
        config['email'] = {
            'enable_notifications': 'true',
            'notification_days_before': '7',
            'template_path': template_path,
            'to_address': 'test@example.com',
            'from_address': 'ssh-key-cop@example.com',
            'smtp_server': 'localhost',  # Using localhost to avoid actual email sending
            'smtp_port': '25',
            'use_tls': 'false',
            'notify_admin': 'true'
        }
        
        # Add user email mappings
        config['user_emails'] = {
            'user1': 'user1@example.com',
            'user2': 'user2@example.com',
            'user3': 'user3@example.com'
        }
    
    with open(config_path, 'w') as f:
        config.write(f)
    
    return config_path


def setup_test_environment(enable_expiration=False, enable_email=False):
    """Create a temporary test environment with simulated user home directories."""
    # Create a temporary directory to simulate /home
    test_home = tempfile.mkdtemp(prefix="ssh_key_cop_test_")
    
    # Create test users
    usernames = ["user1", "user2", "user3"]
    
    for username in usernames:
        user_home = os.path.join(test_home, username)
        ssh_dir = os.path.join(user_home, ".ssh")
        os.makedirs(ssh_dir, exist_ok=True)
        
        # Create authorized_keys file
        with open(os.path.join(ssh_dir, "authorized_keys"), "w") as f:
            # Each user gets a different key
            key_index = usernames.index(username) % len(SAMPLE_KEYS)
            if enable_expiration:
                f.write(SAMPLE_KEYS_WITH_EXPIRATION[key_index] + "\n")
            else:
                f.write(SAMPLE_KEYS[key_index] + "\n")
    
    # Create a test database with an older key
    db_path = os.path.join(test_home, "test_ssh_key_cop.db")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ssh_keys (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            key_signature TEXT NOT NULL,
            first_seen_date TEXT NOT NULL,
            UNIQUE(username, key_signature)
        )
    ''')
    
    # Create email notification tracking table if email is enabled
    if enable_email:
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS email_notifications (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                key_signature TEXT NOT NULL,
                notification_type TEXT NOT NULL,
                sent_date TEXT NOT NULL,
                UNIQUE(username, key_signature, notification_type)
            )
        ''')
    
    # Insert old key for user2 (simulating a key that's older than 30 days)
    old_date = (datetime.datetime.now() - datetime.timedelta(days=45)).isoformat()
    key_signature = SAMPLE_KEYS[1].split()[1]  # Extract key signature
    
    cursor.execute(
        "INSERT INTO ssh_keys (username, key_signature, first_seen_date) VALUES (?, ?, ?)",
        ("user2", key_signature, old_date)
    )
    
    # Insert key that's about to expire (for testing warning notifications)
    if enable_email:
        about_to_expire = (datetime.datetime.now() - datetime.timedelta(days=25)).isoformat()
        key_signature = SAMPLE_KEYS[0].split()[1]  # Extract key signature
        
        cursor.execute(
            "INSERT INTO ssh_keys (username, key_signature, first_seen_date) VALUES (?, ?, ?)",
            ("user1", key_signature, about_to_expire)
        )
    
    conn.commit()
    conn.close()
    
    # Create test configuration
    config_path = create_test_config(test_home, db_path, enable_expiration, enable_email)
    
    return test_home, db_path, config_path


def run_ssh_key_cop(test_home, config_path):
    """Run the SSH Key Cop script against our test environment."""
    # Create a script that monkeypatches the home directory path for testing
    test_script = os.path.join(test_home, "run_test.py")
    
    # Get the absolute path to the ssh_key_cop.py script
    current_dir = os.path.dirname(os.path.abspath(__file__))
    ssh_key_cop_path = os.path.join(current_dir, "ssh_key_cop.py")
    
    with open(test_script, "w") as f:
        f.write(f'''
import os
import sys
import importlib.util
import re

# Import ssh_key_cop.py as a module using its file path
spec = importlib.util.spec_from_file_location("ssh_key_cop", "{ssh_key_cop_path}")
ssh_key_cop = importlib.util.module_from_spec(spec)
sys.modules["ssh_key_cop"] = ssh_key_cop
spec.loader.exec_module(ssh_key_cop)

# Monkey patch the get_all_user_homes method for testing
original_get_all_user_homes = ssh_key_cop.SSHKeyCop.get_all_user_homes
def patched_get_all_user_homes(self):
    users = []
    for user_home in os.listdir("{test_home}"):
        if os.path.isdir(os.path.join("{test_home}", user_home)):
            users.append(user_home)
    self.logger.info(f"Found {{len(users)}} user home directories")
    return users
ssh_key_cop.SSHKeyCop.get_all_user_homes = patched_get_all_user_homes

# Monkey patch the parse_authorized_keys method for testing
original_parse_auth_keys = ssh_key_cop.SSHKeyCop.parse_authorized_keys
def patched_parse_auth_keys(self, username):
    auth_keys_path = os.path.join("{test_home}", username, ".ssh", "authorized_keys")
    key_info = []
    
    if not os.path.exists(auth_keys_path):
        self.logger.debug(f"No authorized_keys file found for user {{username}}")
        return []
    
    try:
        with open(auth_keys_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Check for expiration-time directive
                expiration_date = None
                if 'expiry-time=' in line:
                    pattern = r'expiry-time=([0-9]{{12}})'
                    match = re.search(pattern, line)
                    if match:
                        expiration_date = match.group(1)
                        # Remove the directive from the line for key parsing
                        line = re.sub(r'expiry-time=[0-9]{{12}}\\s+', '', line)
                
                # The key is in the format "type signature comment"
                parts = line.split()
                if len(parts) >= 2:
                    key_signature = parts[1]
                    key_info.append((key_signature, expiration_date))
    except Exception as e:
        self.logger.error(f"Error reading authorized_keys for {{username}}: {{e}}")
        
    self.logger.debug(f"Found {{len(key_info)}} keys for user {{username}}")
    return key_info
ssh_key_cop.SSHKeyCop.parse_authorized_keys = patched_parse_auth_keys

# Monkey patch the send_email method to simulate email sending for testing
if hasattr(ssh_key_cop.SSHKeyCop, 'send_email'):
    original_send_email = ssh_key_cop.SSHKeyCop.send_email
    def patched_send_email(self, subject, message_body, to_address=None):
        # Instead of sending an actual email, just log it
        self.logger.info(f"[TEST] Would send email with subject: {{subject}}")
        self.logger.info(f"[TEST] To: {{to_address}}")
        self.logger.debug(f"[TEST] Email body: {{message_body[:100]}}...")
        
        # Write the email to a file for inspection
        emails_dir = os.path.join("{test_home}", "sent_emails")
        os.makedirs(emails_dir, exist_ok=True)
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        email_path = os.path.join(emails_dir, f"{{timestamp}}_{{subject.replace(' ', '_')}}.txt")
        
        with open(email_path, 'w') as f:
            f.write(f"To: {{to_address}}\\n")
            f.write(f"Subject: {{subject}}\\n")
            f.write("\\n")
            f.write(message_body)
        
        self.logger.info(f"[TEST] Email saved to {{email_path}}")
    ssh_key_cop.SSHKeyCop.send_email = patched_send_email

# Run SSH Key Cop with our test arguments
sys.argv = ["ssh_key_cop.py", "-c", "{config_path}", "-v", "--dry-run"]
ssh_key_cop.main()
        ''')
    
    # Now run the test script
    subprocess.run([sys.executable, test_script])


def cleanup_test_environment(test_home):
    """Clean up the temporary test files."""
    shutil.rmtree(test_home)


def main():
    parser = argparse.ArgumentParser(description="Test SSH Key Cop functionality")
    parser.add_argument("--keep-files", action="store_true",
                        help="Keep the test files after running (for debugging)")
    parser.add_argument("--test-expiration", action="store_true",
                        help="Test the expiration date functionality")
    parser.add_argument("--test-email", action="store_true",
                        help="Test the email notification functionality")
    
    args = parser.parse_args()
    
    print("Setting up test environment...")
    test_home, db_path, config_path = setup_test_environment(args.test_expiration, args.test_email)
    print(f"Test environment created at: {test_home}")
    print(f"Test database: {db_path}")
    print(f"Test config: {config_path}")
    
    try:
        print("\nRunning SSH Key Cop on test environment...")
        run_ssh_key_cop(test_home, config_path)
        
        print("\nTest completed!")
        print("To examine the results or run manually:")
        print(f"1. Check the database: sqlite3 {db_path}")
        print(f"2. Examine the test home directory: ls -la {test_home}")
        print(f"3. Run with different options: python {test_home}/run_test.py")
    finally:
        if not args.keep_files:
            print("\nCleaning up test environment...")
            cleanup_test_environment(test_home)
        else:
            print(f"\nKeeping test files in: {test_home}")


if __name__ == "__main__":
    main() 
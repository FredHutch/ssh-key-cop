#!/usr/bin/env python3
"""
SSH Key Cop - A utility to monitor and enforce SSH key rotation policies.

This script checks for SSH keys in authorized_keys files that are older than a specified
threshold and reports violations.
"""

import argparse
import configparser
import datetime
import glob
import logging
import os
import re
import smtplib
import sqlite3
import sys
from email.message import EmailMessage
from pathlib import Path
from typing import Dict, List, Optional, Tuple


class SSHKeyCop:
    """Main class for SSH Key Cop functionality."""

    def __init__(self, config_path: str, dry_run: bool = False):
        """
        Initialize the SSH Key Cop.

        Args:
            config_path: Path to the configuration file.
            dry_run: If True, don't send emails or update the database.
        """
        # Set up logging first
        self.setup_logging()
        
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
            
        self.config = configparser.ConfigParser()
        self.config.read(config_path)
        
        self.db_path = self.config.get('database', 'path')
        self.days_threshold = self.config.getint('keys', 'expiration_days')
        self.enable_expiration_dates = self.config.getboolean('keys', 'enable_expiration_dates', fallback=False)
        self.logger.info(f"Expiration dates enabled: {self.enable_expiration_dates}")
        self.email_to = self.config.get('email', 'to_address')
        self.email_from = self.config.get('email', 'from_address')
        self.smtp_server = self.config.get('email', 'smtp_server')
        self.smtp_port = self.config.getint('email', 'smtp_port')
        self.smtp_username = self.config.get('email', 'smtp_username', fallback=None)
        self.smtp_password = self.config.get('email', 'smtp_password', fallback=None)
        self.smtp_use_tls = self.config.getboolean('email', 'use_tls', fallback=False)
        
        # If username or password are empty strings, set them to None
        if not self.smtp_username:
            self.smtp_username = None
        if not self.smtp_password:
            self.smtp_password = None
            
        self.dry_run = dry_run
        self.conn = None
        self.cursor = None
        self.setup_database()

    def setup_logging(self):
        """Set up logging configuration."""
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            handlers=[logging.StreamHandler()]
        )
        self.logger = logging.getLogger("ssh-key-cop")

    def setup_database(self):
        """Connect to the database and create tables if they don't exist."""
        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()
        
        # Create tables if they don't exist
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS ssh_keys (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                key_signature TEXT NOT NULL,
                first_seen_date TEXT NOT NULL,
                UNIQUE(username, key_signature)
            )
        ''')
        self.conn.commit()
        self.logger.info(f"Connected to database: {self.db_path}")

    def close_database(self):
        """Close the database connection."""
        if self.conn:
            self.conn.close()
            self.logger.debug("Database connection closed")

    def get_all_user_homes(self) -> List[str]:
        """
        Get a list of all user home directories.
        
        Returns:
            List of usernames
        """
        users = []
        for user_home in glob.glob("/home/*"):
            if os.path.isdir(user_home):
                username = os.path.basename(user_home)
                users.append(username)
        
        self.logger.info(f"Found {len(users)} user home directories")
        return users

    def calculate_expiration_date(self, first_seen_date: str) -> str:
        """
        Calculate the expiration date for a key based on its first seen date.
        
        Args:
            first_seen_date: ISO format date string when the key was first seen
            
        Returns:
            Expiration date in YYYYMMDDHHMM format
        """
        first_seen = datetime.datetime.fromisoformat(first_seen_date)
        expiration = first_seen + datetime.timedelta(days=self.days_threshold)
        return expiration.strftime("%Y%m%d%H%M")

    def parse_authorized_keys(self, username: str) -> List[Tuple[str, Optional[str]]]:
        """
        Parse the authorized_keys file for a given user.
        
        Args:
            username: The username to check
            
        Returns:
            List of tuples containing (key_signature, expiration_date) from authorized_keys file
        """
        auth_keys_path = f"/home/{username}/.ssh/authorized_keys"
        key_info = []
        
        if not os.path.exists(auth_keys_path):
            self.logger.debug(f"No authorized_keys file found for user {username}")
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
                        match = re.search(r'expiry-time="([0-9]{12})"', line)
                        if match:
                            expiration_date = match.group(1)
                            # Remove the directive from the line for key parsing
                            line = re.sub(r'expiry-time="[0-9]{12}"\s+', '', line)
                    
                    # The key is in the format "type signature comment"
                    parts = line.split()
                    if len(parts) >= 2:
                        key_signature = parts[1]
                        key_info.append((key_signature, expiration_date))
        except Exception as e:
            self.logger.error(f"Error reading authorized_keys for {username}: {e}")
            
        self.logger.debug(f"Found {len(key_info)} keys for user {username}")
        return key_info

    def is_key_expired(self, first_seen_date: str) -> bool:
        """
        Check if a key has expired based on the first seen date.
        
        Args:
            first_seen_date: ISO format date string when the key was first seen
            
        Returns:
            True if the key has expired, False otherwise
        """
        first_seen = datetime.datetime.fromisoformat(first_seen_date)
        now = datetime.datetime.now()
        days_old = (now - first_seen).days
        
        return days_old > self.days_threshold

    def add_key_to_database(self, username: str, key_signature: str) -> None:
        """
        Add a new key to the database.
        
        Args:
            username: The username the key belongs to
            key_signature: The SSH key signature
        """
        if self.dry_run:
            self.logger.info(f"[DRY RUN] Would add new key for {username}")
            return
            
        now = datetime.datetime.now().isoformat()
        
        try:
            self.cursor.execute(
                "INSERT OR IGNORE INTO ssh_keys (username, key_signature, first_seen_date) VALUES (?, ?, ?)",
                (username, key_signature, now)
            )
            self.conn.commit()
            self.logger.info(f"Added new key for user {username}")
        except sqlite3.Error as e:
            self.logger.error(f"Database error adding key for {username}: {e}")

    def get_key_info(self, username: str, key_signature: str) -> Optional[Tuple[str, str, str]]:
        """
        Get information about a key from the database.
        
        Args:
            username: The username to check
            key_signature: The SSH key signature
            
        Returns:
            Tuple of (id, username, first_seen_date) or None if not found
        """
        try:
            self.cursor.execute(
                "SELECT id, username, first_seen_date FROM ssh_keys WHERE username = ? AND key_signature = ?",
                (username, key_signature)
            )
            result = self.cursor.fetchone()
            return result
        except sqlite3.Error as e:
            self.logger.error(f"Database error retrieving key info: {e}")
            return None

    def send_violation_email(self, violations: List[Dict]) -> None:
        """
        Send email about key violations.
        
        Args:
            violations: List of dictionaries with violation information
        """
        if not violations:
            return
            
        if self.dry_run:
            self.logger.info(f"[DRY RUN] Would send email with {len(violations)} violations")
            return
            
        try:
            msg = EmailMessage()
            msg['Subject'] = 'SSH Key Rotation Violations'
            msg['From'] = self.email_from
            msg['To'] = self.email_to
            
            body = "The following SSH keys have not been rotated in over " \
                  f"{self.days_threshold} days:\n\n"
                  
            for v in violations:
                body += f"User: {v['username']}\n"
                body += f"Key: {v['key_signature']}\n"
                body += f"First seen: {v['first_seen_date']}\n"
                body += f"Age: {v['days_old']} days\n\n"
                
            body += "\nPlease ensure these keys are rotated as soon as possible."
            
            msg.set_content(body)
            
            # Send email using configured SMTP server
            try:
                if self.smtp_username and self.smtp_password:
                    # Use authentication
                    if self.smtp_use_tls:
                        with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                            server.starttls()
                            server.login(self.smtp_username, self.smtp_password)
                            server.send_message(msg)
                    else:
                        with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                            server.login(self.smtp_username, self.smtp_password)
                            server.send_message(msg)
                else:
                    # No authentication needed
                    with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                        server.send_message(msg)
                
                self.logger.info(f"Sent violation report to {self.email_to}")
            except Exception as e:
                self.logger.error(f"Failed to send email: {e}")
                # Still log the email content
                self.logger.info(f"Email content that would have been sent: {body}")
                
        except Exception as e:
            self.logger.error(f"Error preparing email: {e}")

    def update_authorized_keys(self, username: str, key_signatures: List[Tuple[str, Optional[str]]]) -> None:
        """
        Update the authorized_keys file with expiration dates.
        
        Args:
            username: The username to update
            key_signatures: List of tuples containing (key_signature, expiration_date)
        """
        if not self.enable_expiration_dates:
            self.logger.debug("Expiration dates are disabled, skipping update")
            return
            
        auth_keys_path = f"/home/{username}/.ssh/authorized_keys"
        if not os.path.exists(auth_keys_path):
            self.logger.warning(f"Authorized_keys file not found for {username}")
            return
            
        try:
            # Read the original file
            with open(auth_keys_path, 'r') as f:
                original_lines = f.readlines()
            
            # Create a mapping of key signatures to their full lines
            key_to_line = {}
            comments = []
            for line in original_lines:
                line = line.strip()
                if not line:
                    continue
                if line.startswith('#'):
                    comments.append(line)
                    continue
                
                # Extract key signature
                parts = line.split()
                if len(parts) >= 2:
                    # Handle lines with expiration dates
                    if 'expiry-time=' in line:
                        # Remove the expiration date for key matching
                        clean_line = re.sub(r'expiry-time="[0-9]{12}"\s+', '', line)
                        parts = clean_line.split()
                    
                    if len(parts) >= 2:
                        key_sig = parts[1]
                        key_to_line[key_sig] = line
            
            # Update lines with expiration dates
            updated_lines = []
            # Add back comments at the top
            updated_lines.extend(comments)
            
            # Create a set of keys that need updates
            keys_to_update = {k[0] for k in key_signatures if k[1] is not None}
            
            for key_sig, exp_date in key_signatures:
                if key_sig in key_to_line:
                    line = key_to_line[key_sig]
                    if key_sig in keys_to_update:
                        # Only update lines that need changes
                        if 'expiry-time=' in line:
                            line = re.sub(r'expiry-time="[0-9]{12}"\s+', f'expiry-time="{exp_date}" ', line)
                        else:
                            line = f'expiry-time="{exp_date}" {line}'
                        self.logger.info(f"Adding expiration date {exp_date} to key for {username}")
                    updated_lines.append(line + '\n')
            
            if self.dry_run:
                self.logger.info(f"[DRY RUN] Would update authorized_keys for {username}")
                return
                
            # Write the updated file
            with open(auth_keys_path, 'w') as f:
                f.writelines(updated_lines)
                
            self.logger.info(f"Updated authorized_keys for user {username}")
        except Exception as e:
            self.logger.error(f"Error updating authorized_keys for {username}: {e}")
            self.logger.error(f"Error details: {str(e)}")

    def check_all_users(self) -> List[Dict]:
        """
        Check all users for SSH key violations.
        
        Returns:
            List of violation dictionaries
        """
        violations = []
        
        for username in self.get_all_user_homes():
            key_info_list = self.parse_authorized_keys(username)
            key_signatures = [k[0] for k in key_info_list]
            
            # Track which keys need updates
            keys_to_update = []
            
            for key_sig, exp_date in key_info_list:
                db_key_info = self.get_key_info(username, key_sig)
                
                if db_key_info is None:
                    # New key, add to database
                    self.add_key_to_database(username, key_sig)
                    if self.enable_expiration_dates:
                        # Calculate expiration date for new key
                        now = datetime.datetime.now().isoformat()
                        new_exp_date = self.calculate_expiration_date(now)
                        keys_to_update.append((key_sig, new_exp_date))
                else:
                    # Existing key, check if expired
                    key_id, db_username, first_seen_date = db_key_info
                    
                    # Calculate expected expiration date
                    expected_exp_date = self.calculate_expiration_date(first_seen_date)
                    
                    # Check if expiration date matches database record
                    if exp_date and exp_date != expected_exp_date:
                        self.logger.warning(
                            f"Key expiration date mismatch for {username}: "
                            f"expected {expected_exp_date}, found {exp_date}"
                        )
                        keys_to_update.append((key_sig, expected_exp_date))
                    elif not exp_date and self.enable_expiration_dates:
                        # Add expiration date to key without one
                        keys_to_update.append((key_sig, expected_exp_date))
                    
                    if self.is_key_expired(first_seen_date):
                        first_seen = datetime.datetime.fromisoformat(first_seen_date)
                        now = datetime.datetime.now()
                        days_old = (now - first_seen).days
                        
                        violation = {
                            'username': username,
                            'key_signature': key_sig,
                            'first_seen_date': first_seen_date,
                            'days_old': days_old
                        }
                        violations.append(violation)
                        self.logger.warning(
                            f"Key violation: {username}'s key is {days_old} days old "
                            f"(first seen: {first_seen_date})"
                        )
            
            # Update keys that need changes
            if keys_to_update and self.enable_expiration_dates:
                # Create updated key info list with new expiration dates
                updated_key_info = []
                for key_sig, exp_date in key_info_list:
                    # Find if this key needs an update
                    update = next((k for k in keys_to_update if k[0] == key_sig), None)
                    if update:
                        updated_key_info.append((key_sig, update[1]))
                    else:
                        updated_key_info.append((key_sig, exp_date))
                
                self.update_authorized_keys(username, updated_key_info)
        
        return violations

    def print_database_contents(self) -> None:
        """Print the contents of the database."""
        self.cursor.execute("SELECT username, key_signature, first_seen_date FROM ssh_keys")
        rows = self.cursor.fetchall()
        
        if not rows:
            print("No keys in database.")
            return
            
        print(f"{'Username':<20} {'First Seen':<25} {'Days Old':<10} {'Key Signature'}")
        print("-" * 80)
        
        now = datetime.datetime.now()
        
        for row in rows:
            username, key_sig, first_seen_date = row
            first_seen = datetime.datetime.fromisoformat(first_seen_date)
            days_old = (now - first_seen).days
            
            # Truncate key signature for display
            key_short = key_sig[:40] + "..." if len(key_sig) > 40 else key_sig
            
            print(f"{username:<20} {first_seen_date:<25} {days_old:<10} {key_short}")

    def run(self) -> None:
        """Run the main program logic."""
        violations = self.check_all_users()
        
        if violations:
            self.logger.warning(f"Found {len(violations)} key violations")
            self.send_violation_email(violations)
        else:
            self.logger.info("No key violations found")


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(description="SSH Key Cop - Monitor SSH key rotation")
    parser.add_argument("-c", "--config", default="ssh_key_cop.ini",
                        help="Path to the configuration file")
    parser.add_argument("--dry-run", action="store_true",
                        help="Run without modifying the database or sending emails")
    parser.add_argument("--dump", action="store_true",
                        help="Dump the contents of the database and exit")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose output")
    
    args = parser.parse_args()
    
    # Set logging level based on verbose flag
    if args.verbose:
        logging.getLogger("ssh-key-cop").setLevel(logging.DEBUG)
    
    try:
        keycop = SSHKeyCop(
            config_path=args.config,
            dry_run=args.dry_run
        )
        
        try:
            if args.dump:
                keycop.print_database_contents()
            else:
                keycop.run()
        finally:
            keycop.close_database()
    except FileNotFoundError as e:
        print(f"Error: {e}")
        print(f"Please create a configuration file at: {args.config}")
        print(f"You can copy the sample file: ssh_key_cop.ini.sample")
        sys.exit(1)


if __name__ == "__main__":
    main() 
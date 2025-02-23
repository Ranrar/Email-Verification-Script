#!/usr/bin/env python3
# Email Verification Script
# Copyright (C) 2025 Kim Skov Rasmussen
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

import sys
import subprocess
from functools import wraps
import time
from collections import deque
from contextlib import contextmanager
import queue
import logging
from config import Config
from datetime import datetime, timedelta
from functools import wraps
from cryptography.fernet import Fernet
from database import Database
import getpass

def ttl_cache(maxsize=128, ttl=600):
    """Time-based cache decorator with maximum size limit"""
    cache = {}
    timestamps = {}
    
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            key = str(args) + str(kwargs)
            
            # Check if cached and not expired
            now = datetime.now()
            if key in cache:
                if now - timestamps[key] < timedelta(seconds=ttl):
                    return cache[key]
                else:
                    # Remove expired entry
                    del cache[key]
                    del timestamps[key]
            
            # Add new entry
            result = func(*args, **kwargs)
            cache[key] = result
            timestamps[key] = now
            
            # Remove oldest entries if cache is full
            while len(cache) > maxsize:
                oldest_key = min(timestamps, key=timestamps.get)
                del cache[oldest_key]
                del timestamps[oldest_key]
            
            return result
        return wrapper
    return decorator

# Create a config instance
config = Config()

# Define SCRIPT_IDENTITY
SCRIPT_IDENTITY = {
    'User-Agent': config.USER_AGENT,
    'From': f"Email: {config.USER_CREDENTIALS.USER_EMAIL}"
}

# List required external dependencies (modules not included in the standard library)
required_dependencies = ["dns", "requests", "tabulate", "sqlite3", "cryptography"]
missing_dependencies = []

for dep in required_dependencies:
    try:
        __import__(dep)
    except ImportError:
        missing_dependencies.append(dep)

if (missing_dependencies):
    print("Missing dependencies: " + ", ".join(missing_dependencies))
    choice = input("Do you want to install them? (Y/N): ")
    if choice.lower() in ["y", "yes"]:
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "--user", *missing_dependencies]
            )
            print("Dependencies installed successfully. Please restart the script.")
        except Exception as e:
            print("Error installing dependencies:", e)
    sys.exit(0)

# Continue with the rest of the script once all dependencies are present.
import os
import platform
import socket
import dns.resolver
import smtplib
import re
import requests
import csv
from datetime import datetime
import time
import imaplib
import poplib
import webbrowser
import configparser
from tabulate import tabulate
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from typing import Optional, List

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('program.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Name of the log file
LOG_FILE = "log.txt"

# Update LOG_HEADER definition
LOG_HEADER = ["ID"] + [
    col.name 
    for col in config.LOG_COLUMNS.values()
    if col.show.upper() == 'Y'
]

# List of known blacklisted domains (for demonstration)
BLACKLISTED_DOMAINS = {
    "blacklisted.com": ["Spamhaus", "Barracuda", "SpamCop"],
    "baddomain.net": ["Spamhaus", "SORBS"],
    "malicious.org": ["SpamCop", "Spamhaus"]
}

# --- Other Script Definitions ---

def clear_screen():
    # Check the operating system and use the appropriate command
    if platform.system() == "Windows":
        os.system('cls')  # Windows
    else:
        os.system('clear')  # Linux and macOS
# --- Help ---
  
def display_help():
    """Display custom help text."""
    help_command = (
        "\n"
        "Usage:\n"
        "----------------------------------------------------------------------\n"
        "  - Enter one or more email addresses separated by commas to check their validity.\n"
        "  - For example: test@example.com, user@domain.com\n"
        "\n"
        "Or Type:\n"
        "\n"
        "  - 'help' to display this help message.\n"
        "  - 'exit' to quit the program.\n"
        "  - 'show log' to display a simple list of logged emails and their validation status.\n"    
        "  - 'clear log' Delete all content from the log file.\n"    
        "  - 'log help' to display how the log works\n"
        "  - 'read more' to learn more about: Key Features and Functions, What to Expect and Use Cases\n"
        "  - 'clear' to clear the terminal window\n"        
        "\n"
    )
    print(help_command)
    
# Replace the display_log_help function to remove INI file references
def display_log_help():
    """Display custom help text."""
    help_log = ( 
        "\n"
        "Log file details:\n"
        "----------------------------------------------------------------------\n"
        "  - All email validation checks are logged to `log.txt`.\n"
        "  - Each log entry is in CSV format and includes details such as:\n"
        "    • Timestamp of the check\n"
        "    • Email address and associated domain\n"
        "    • MX record and the port used for verification\n"
        "    • Disposable email status, SPF and DKIM results\n"
        "    • SMTP and VRFY outcomes, catch-all detection, and blacklist info\n"
        "    • Additional technical details like SMTP banner, MX IP, and IMAP/POP3 status\n"
        "  - Reviewing this file can help diagnose issues and confirm the results of the validation process.\n"
        "\n"
        "Log Display Categories:\n"
        "\n"
        "  Core Information: Essential data about the email check\n"
        "  Security Checks: Security-related verification results\n"
        "  Technical Details: Detailed technical information\n"
        "  Protocol Status: Email protocol support information\n"
        "  Metadata: Timestamp and counter information\n"
        "\n"
    )
    print(help_log)

# --- Disposable and Blacklist Detection ---

def is_disposable_email(email):
    """Check if the email is from a disposable email provider."""
    domain = email.split('@')[1].lower()
    return domain in config.DISPOSABLE_DOMAINS

# Update blacklist checking
def check_blacklists(email):
    """Check if the email's domain is blacklisted."""
    domain = email.split('@')[1].lower()
    if domain in config.BLACKLISTED_DOMAINS:
        return ", ".join(config.BLACKLISTED_DOMAINS[domain])
    else:
        return "Not Blacklisted"

# --- DNS and SMTP Functions ---

@ttl_cache(maxsize=1000, ttl=3600)  # Cache for 1 hour
def get_mx_record(domain: str) -> Optional[List[dns.resolver.Answer]]:
    """Cached MX record lookup"""
    try:
        answers = dns.resolver.resolve(domain, 'MX', lifetime=10)
        return sorted(answers, key=lambda x: x.preference)
    except Exception as e:
        logger.error(f"DNS resolution error for {domain}: {e}")
        return None

def check_spf(domain):
    """Check for SPF record in domain's TXT records."""
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            if "v=spf1" in str(rdata):
                return "SPF Found"
        return "No SPF Record"
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return "No SPF Record"

def check_dkim(domain):
    """Check for DKIM TXT record in domain's DNS settings."""
    dkim_selector = "default"  # Common selector; adjust if needed
    dkim_domain = f"{dkim_selector}._domainkey.{domain}"
    try:
        answers = dns.resolver.resolve(dkim_domain, 'TXT')
        for rdata in answers:
            if "v=DKIM1" in str(rdata):
                return "DKIM Found"
        return "No DKIM Record"
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return "No DKIM Record"

def rate_limiter(max_requests=None, time_window=None):
    """Rate limiter using sliding window."""
    def decorator(func):
        requests = deque(maxlen=max_requests)
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Use config values if not specified
            _max_requests = max_requests or config.RATE_LIMIT_REQUESTS
            _time_window = time_window or config.RATE_LIMIT_WINDOW
            
            now = time.time()
            
            # Remove old requests
            while requests and now - requests[0] > _time_window:
                requests.popleft()
                
            # Check if we've hit the limit
            if len(requests) >= _max_requests:
                wait_time = requests[0] + _time_window - now
                if wait_time > 0:
                    logger.warning(f"Rate limit reached. Waiting {wait_time:.2f} seconds...")
                    time.sleep(wait_time)
            
            result = func(*args, **kwargs)
            requests.append(now)
            return result
        return wrapper
    return decorator

# Apply rate limiting to key functions
# Replace hardcoded values with config values in test_smtp_connection
@rate_limiter()  # Uses default config values
def test_smtp_connection(server, port, email, retries=config.MAX_RETRIES):
    """Test SMTP connection to a server"""
    timeout = config.SMTP_TIMEOUT
    for attempt in range(retries):
        try:
            with smtplib.SMTP(server, port, timeout=timeout) as smtp:
                smtp.ehlo()
                smtp.mail("test@domain.com")
                code, _ = smtp.rcpt(email)
                if code == 250:
                    return True
        except Exception as e:
            print(f"SMTP connection error on attempt {attempt + 1} for {server}:{port} - {e}")
            time.sleep(2)  # Increase sleep duration between retries
            continue
    return False

# Update rate limits for specific operations
@rate_limiter(
    max_requests=config.RATE_LIMITS['smtp_connections'][0],
    time_window=config.RATE_LIMITS['smtp_connections'][1]
)
def smtp_vrfy(server, port, email):
    """Attempt SMTP VRFY command to check if the email exists."""
    try:
        with smtplib.SMTP(server, port, timeout=10) as smtp:
            smtp.ehlo()
            code, msg = smtp.verify(email)
            if isinstance(msg, bytes):
                msg = msg.decode()
            return code, msg
    except Exception as e:
        return None, str(e)

# --- Additional Technical Details Functions ---

def get_smtp_banner(server):
    """Get the SMTP banner by trying HELLO and then EHLO commands, removing newlines."""
    try:
        with smtplib.SMTP(server, timeout=10) as smtp:
            banner = smtp.docmd("HELLO")
            if banner[0] == 250:
                result = banner[1].decode() if banner else "No banner"
            else:
                banner = smtp.ehlo()
                result = banner[1].decode() if banner else "No banner"
            return result.replace("\n", " ").strip()
    except Exception as e:
        return str(e)

def get_mx_ip(server):
    """Get the IP address of the MX server."""
    try:
        ip = socket.gethostbyname(server)
        return ip
    except socket.gaierror:
        return "Unknown IP"

# --- New Protocol Check Functions (IMAP/POP3) ---

def check_imap_ssl(server):
    """Check if the server supports IMAP over SSL on port 993."""
    try:
        imap = imaplib.IMAP4_SSL(server, 993, timeout=5)
        banner = imap.welcome.decode() if isinstance(imap.welcome, bytes) else imap.welcome
        imap.logout()
        return "Available", banner.replace("\n", " ").strip()
    except Exception as e:
        return "Not available", str(e)

def check_pop3_ssl(server):
    """Check if the server supports POP3 over SSL on port 995."""
    try:
        pop = poplib.POP3_SSL(server, 995, timeout=5)
        banner = pop.getwelcome().decode() if isinstance(pop.getwelcome(), bytes) else pop.getwelcome()
        pop.quit()
        return "Available", banner.replace("\n", " ").strip()
    except Exception as e:
        return "Not available", str(e)

def check_server_policies(domain: str) -> bool:
    """Check if the domain has any specific anti-verification policies"""
    # Implementation would check for:
    # - RFC 7208 (SPF) policy
    # - DMARC policy
    # - Server banners indicating no verification
    pass

# --- Logging Functions ---
# Log Order:
# Timestamp, Email Address, Domain, MX Record, Used Port, Disposable Email, SPF Status, DKIM Status,
# Catch-all Email, SMTP Result, SMTP VRFY Result, Blacklist Info, MX Preferences, SMTP Banner, MX IP,
# Error Message

def sanitize_log_entry(value):
    """Sanitize log entry to prevent CSV injection and remove problematic characters"""
    if value is None:
        return ""
    
    # Convert to string and clean up
    value = str(value)
    value = value.replace('\n', ' ').replace('\r', ' ')
    value = value.replace(',', ';')  # Replace commas with semicolons
    value = re.sub(r'\s+', ' ', value)  # Replace multiple spaces with single space
    return value.strip()

def log_email_check(email, mx_record, spf_status, dkim_status, smtp_result, port, domain, **kwargs):
    """Log email verification results to database"""
    data = {
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'email': email,
        'domain': domain,
        'result': smtp_result,
        'mx_record': mx_record,
        'port': port,
        'disposable': kwargs.get('disposable_status', ''),
        'spf_status': spf_status,
        'dkim_status': dkim_status,
        'catch_all': kwargs.get('catch_all_email', ''),
        'smtp_result': smtp_result,
        'smtp_vrfy': kwargs.get('smtp_vrfy_result', ''),
        'blacklist_info': kwargs.get('blacklist_info', ''),
        'mx_preferences': kwargs.get('mx_preferences', ''),
        'smtp_banner': kwargs.get('smtp_banner', ''),
        'mx_ip': kwargs.get('mx_ip', ''),
        'error_message': kwargs.get('error_message', ''),
        'imap_status': kwargs.get('imap_status', ''),
        'imap_banner': kwargs.get('imap_banner', ''),
        'pop3_status': kwargs.get('pop3_status', ''),
        'pop3_banner': kwargs.get('pop3_banner', '')
    }
    
    try:
        db = Database(config)
        db.log_check(data)
    except Exception as e:
        logger.error(f"Failed to log email check: {e}")

def check_existing_log_for_domain(domain):
    """Check log.txt for a previous check for the domain and return a valid port if found."""
    if not os.path.isfile(LOG_FILE):
        return None
    with open(LOG_FILE, mode="r", newline="") as file:
        reader = csv.reader(file)
        try:
            next(reader)  # Skip header row
        except StopIteration:
            return None
        for row in reader:
            if len(row) >= 8:
                try:
                    if row[3].strip().lower() == domain.strip().lower():
                        port_value = row[5].strip()
                        if port_value and port_value.upper() != "N/A":
                            return port_value
                except IndexError:
                    continue
    return None

# --- Email Validation Functions ---

def check_smtp_with_port(domain, email, port):
    """Check the SMTP server with a specific port."""
    mx_records = get_mx_record(domain)
    if (mx_records):
        for mx in mx_records:
            server = str(mx.exchange).rstrip('.')
            if test_smtp_connection(server, port, email):
                return "Email likely exists"
    return "Could not verify email"

def validate_email(email):
    """Enhanced email validation with logging"""
    logger.info(f"Starting validation for email: {email}")
    try:
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            log_email_check(email, "Invalid Format", "N/A", "N/A", "Invalid Email Format",
                            "N/A", "N/A", error_message="Invalid email format", blacklist_info=check_blacklists(email))
            return "Invalid email format."
        
        domain = email.split('@')[1]
        disposable_status = "Disposable" if is_disposable_email(email) else "Not Disposable"
        blacklist_info = check_blacklists(email)
        
        smtp_vrfy_result = ""
        catch_all_email = ""
        mx_preferences = ""
        smtp_banner = ""
        mx_ip = ""
        
        # Check for cached valid port
        existing_port = check_existing_log_for_domain(domain)
        if existing_port:
            print(f"Using cached port {existing_port} for domain {domain}.")
            smtp_result = check_smtp_with_port(domain, email, int(existing_port))
            code, vrfy_msg = smtp_vrfy(str(get_mx_record(domain)[0].exchange).rstrip('.'),
                                    int(existing_port), email)
            smtp_vrfy_result = "Verified" if code == 250 else "Not Verified"
            if smtp_result == "Email likely exists":
                fake_email = f"nonexistent{int(time.time())}@{domain}"
                if test_smtp_connection(str(get_mx_record(domain)[0].exchange).rstrip('.'),
                                        int(existing_port), fake_email):
                    smtp_result = "Email likely exists"
                    catch_all_email = fake_email
                    print(f"Catch-all detected: {fake_email} (email likely exists)")
            mx_preferences = ", ".join([str(mx.preference) for mx in get_mx_record(domain)])
            smtp_banner = get_smtp_banner(str(get_mx_record(domain)[0].exchange).rstrip('.'))
            mx_ip = get_mx_ip(str(get_mx_record(domain)[0].exchange).rstrip('.'))
            
            log_email_check(email, "MX Found", check_spf(domain), check_dkim(domain),
                            smtp_result, existing_port, domain, error_message="",
                            catch_all_email=catch_all_email, disposable_status=disposable_status,
                            smtp_vrfy_result=smtp_vrfy_result, blacklist_info=blacklist_info,
                            mx_preferences=mx_preferences, smtp_banner=smtp_banner, mx_ip=mx_ip)
            return smtp_result

        print(f"Checking MX records for {domain}...")
        mx_records = get_mx_record(domain)
        if not mx_records:
            log_email_check(email, "No MX Records", "N/A", "N/A", "Could not verify email", "N/A", domain,
                            error_message="No MX records found", blacklist_info=blacklist_info, disposable_status=disposable_status,
                            smtp_vrfy_result="N/A", mx_preferences="N/A", smtp_banner="N/A", mx_ip="N/A")
            return "This domain cannot receive emails (no MX records)."
        
        primary_mx = str(mx_records[0].exchange).rstrip('.')
        print(f"Primary MX for {domain} is {primary_mx}.")
        
        spf_status = check_spf(domain)
        dkim_status = check_dkim(domain)
        
        smtp_result = "Could not verify email"
        used_port = "N/A"
        error_message = ""
        
        # Update port testing loop
        for port in config.PORTS_TO_TRY:
            print(f"Testing {domain} on port {port}...")
            if test_smtp_connection(primary_mx, port, email):
                smtp_result = "Email likely exists"
                used_port = port
                break
        if smtp_result == "Email likely exists":
            fake_email = f"nonexistent{int(time.time())}@{domain}"
            if test_smtp_connection(primary_mx, used_port, fake_email):
                smtp_result = "Email likely exists"
                catch_all_email = fake_email
                print(f"Catch-all detected: {fake_email} (email likely exists)")
        else:
            error_message = "SMTP check failed. Could not verify email."
        
        code, vrfy_msg = smtp_vrfy(primary_mx, used_port if used_port != "N/A" else 25, email)
        smtp_vrfy_result = "Verified" if code == 250 else "Not Verified"
        
        mx_preferences = ", ".join([str(mx.preference) for mx in mx_records])
        smtp_banner = get_smtp_banner(primary_mx)
        mx_ip = get_mx_ip(primary_mx)
        imap_status, imap_banner = check_imap_ssl(primary_mx)
        pop3_status, pop3_banner = check_pop3_ssl(primary_mx)
        
        log_email_check(
            email=email,
            mx_record=primary_mx,
            spf_status=spf_status,
            dkim_status=dkim_status,
            smtp_result=smtp_result,
            port=used_port,
            domain=domain,
            error_message=error_message,
            catch_all_email=catch_all_email,
            disposable_status=disposable_status,
            smtp_vrfy_result=smtp_vrfy_result,
            blacklist_info=blacklist_info,
            mx_preferences=mx_preferences,
            smtp_banner=smtp_banner,
            mx_ip=mx_ip,
            imap_status=imap_status,
            imap_banner=imap_banner,
            pop3_status=pop3_status,
            pop3_banner=pop3_banner
        )
        return smtp_result
    except Exception as e:
        logger.error(f"Error validating {email}: {str(e)}", exc_info=True)
        raise

def validate_emails(emails):
    """Validate multiple email addresses in parallel."""
    with ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(validate_email, emails))
    return results

# --- Show log---   

# Update the load_selected_columns function
def load_selected_columns():
    """Load column display settings from config"""
    selected_columns = {}
    
    for column_name, column in config.LOG_COLUMNS.items():
        if column.show:
            selected_columns[column.name] = column.index
    
    return selected_columns

# Replace show_log function with:
def show_log():
    """Display log entries from encrypted database"""
    try:
        columns, rows = db.show_logs()
        if not rows:
            print("No log entries found.\n")
            return

        visible_columns = [
            col for col in columns 
            if col in config.LOG_COLUMNS 
            and config.LOG_COLUMNS[col].show.upper() == 'Y'
        ]

        visible_data = [
            [row[columns.index(col)] for col in visible_columns]
            for row in rows
        ]

        print(tabulate(
            visible_data,
            headers=[config.LOG_COLUMNS[col].display_name for col in visible_columns],
            tablefmt="github",
            numalign="left",
            stralign="left"
        ))
        print()

    except Exception as e:
        logger.error(f"Error displaying log: {str(e)}")
        print(f"Error reading log database: {e}\n")
 
# --- Clear log---        
# Replace clear_log function with:
def clear_log():
    """Clear the email logs table and reset sequence counter with password verification"""
    try:
        # Prompt for password confirmation
        password = getpass.getpass("\nPlease enter your password to confirm log deletion: ")
        
        # Create temporary database connection for verification
        temp_db = Database(config)
        if not temp_db._verify_password(password):
            print("\nInvalid password. Log clearing cancelled.")
            return
            
        # If password is correct, proceed with confirmation
        confirmation = input("\nAre you sure you want to clear all email logs? This cannot be undone. (yes/no): ")
        if confirmation.lower() == 'yes':
            db.clear_email_logs()  # Clear email_logs table
            db.reset_sequence('email_logs')  # Reset sequence counter
            print("\nEmail logs cleared successfully!")
        else:
            print("\nLog clearing cancelled.")
            
    except Exception as e:
        print(f"\nError clearing logs: {str(e)}")

# --- Exit Message ---

EXIT_MESSAGE = (
"======================================================================\n"
    "Email Verification Script has exited.\n"
    "Thank you for using this tool.\n"  
    "Remember: This software is provided as is under GNU GPL v3.\n"
"======================================================================\n"
)

# --- Main Loop ---
def main():
    try:
        global db
        db = Database(config)
        
        # Clear screen and show welcome banner
        clear_screen()
        print("""\
======================================================================
Email Verification Script - Version 1.0
Copyright (C) 2025 Kim Skov Rasmussen
Licensed under GNU General Public License v3.0
This software is provided as is, without any warranties.
Use at your own risk. For educational purposes only.

Please login to continue. Type 'help' for available commands.
======================================================================
""")
        
        # Get password from user only if not authenticated
        if not db.is_authenticated:
            password = getpass.getpass("Password> ")
            
            if not db.authenticate(password):
                print("Authentication failed")
                sys.exit(1)
                
            # Show welcome message with username
            print(f"\nLogin successful! Welcome {db.current_user}\n")
            
    except Exception as e:
        print(f"Database initialization error: {e}")
        sys.exit(1)

    while True:
        user_input = input("Command> ").strip()

        # Handle special commands first
        if user_input.lower() == "exit":
            clear_screen()
            print(EXIT_MESSAGE)  # Display exit message
            break

        elif user_input.lower() == "help":
            display_help()  # Call the function to display help
            continue
            
        elif user_input.lower() == "log help":
            display_log_help()  # Call the function to display log help
            continue

        elif user_input.lower() == "show log":
            show_log()  # Calls the function to display log summary
            continue

        elif user_input.lower() == "read more":
            # Construct the file path and open it in the browser
            file_path = os.path.join(os.getcwd(), "documentation", "README.md")
            webbrowser.open(file_path)
            continue
            
        elif user_input.lower() == "clear log":
            clear_log()  # Calls the function to clear log.txt
            continue
            
        elif user_input.lower() == "clear":
            clear_screen()  # Clear the terminal window
            continue

        elif user_input.lower() == "who am i":
                print(f"Current user: {config.USER_CREDENTIALS.USER_NAME}")
                print(f"User email: {config.USER_CREDENTIALS.USER_EMAIL}")            
                continue

        # Split input by commas and remove empty spaces
        emails = [email.strip() for email in user_input.split(",") if email.strip()]

        # Check if the input contains valid email(s)
        if any("@" in email and "." in email for email in emails):  
            results = validate_emails(emails)
            for email, result in zip(emails, results):
                print(f"{email}: {result}\n")
            continue  # Skip "Unknown command" check

        # If input is neither a known command nor a valid email, show an error
        print("Unknown command. Type 'help' for available commands.")

if __name__ == "__main__":
    main()

class SMTPConnectionPool:
    """SMTP Connection Pool"""
    def __init__(self, max_connections=10):
        self.pool = queue.Queue(maxsize=max_connections)
        self.active_connections = {}

    @contextmanager
    def get_connection(self, host, port):
        try:
            smtp = self.pool.get_nowait()
        except queue.Empty:
            smtp = smtplib.SMTP(timeout=10)
            
        try:
            if not smtp.sock:
                smtp.connect(host, port)
            yield smtp
        finally:
            try:
                self.pool.put_nowait(smtp)
            except queue.Full:
                smtp.quit()

# Create global connection pool
smtp_pool = SMTPConnectionPool(max_connections=config.CONNECTION_POOL_SIZE)

# Initialize database connection (move this near the top with other initializations)
db = None  # Will be initialized in main()
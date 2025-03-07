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
import time
import queue
from collections import deque
from contextlib import contextmanager
from config import Config
from datetime import datetime, timedelta
from functools import wraps
from database import Database
from tabulate import tabulate
from packages.logger.logger import P_Log

_last_execution_time = 0.0

def performance_monitor(func):
    """Decorator to track function performance"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Start timing
        start_time = time.time()
        
        # ALWAYS pass the start time as a keyword argument
        # Make a copy of kwargs to avoid modifying the original
        new_kwargs = kwargs.copy()
        new_kwargs['_start_time'] = start_time
        
        # Call the original function with the new kwargs
        result = func(*args, **new_kwargs)
        
        # Calculate execution time
        execution_time = time.time() - start_time
        
        # Log performance for all functions
        logger.info(f"Performance: {func.__name__} took {execution_time:.2f}s")
            
        return result
    return wrapper

# Optimization: Add periodic cleanup for TTL cache
def ttl_cache(maxsize=128, ttl=600):
    """Time-based cache decorator with maximum size limit"""
    cache = {}
    timestamps = {}
    last_cleanup = datetime.now()
    cleanup_interval = 60  # seconds
    
    def make_key(*args, **kwargs):
        """Create a more efficient cache key"""
        key_parts = [repr(arg) for arg in args]
        key_parts.extend(f"{k}:{repr(v)}" for k, v in sorted(kwargs.items()))
        return hash(tuple(key_parts))
    
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            nonlocal last_cleanup
            key = make_key(*args, **kwargs)
            now = datetime.now()
            
            # Periodically clean expired entries
            if (now - last_cleanup).total_seconds() > cleanup_interval:
                expired_keys = [k for k, ts in timestamps.items() 
                              if now - ts > timedelta(seconds=ttl)]
                for k in expired_keys:
                    if k in cache: del cache[k]
                    if k in timestamps: del timestamps[k]
                last_cleanup = now
            
            # Check if cached and not expired
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
required_dependencies = ["dns", "requests", "tabulate", "sqlite3"]
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
import time
import imaplib
import poplib
import webbrowser
import requests
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from tabulate import tabulate
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from typing import Optional, List

# Initialize logger
logger = P_Log(logger_name='evs', log_to_console=False)

# Define blacklisted and disposable domains
BLACKLISTED_DOMAINS = {
    "blacklisted.com": ["Spamhaus", "Barracuda", "SpamCop"],
    "baddomain.net": ["Spamhaus", "SORBS"],
    "malicious.org": ["SpamCop", "Spamhaus"]
}

# clearer screen function
def clear_screen():
    if platform.system() == "Windows":
        os.system('cls')  # Windows
    else:
        os.system('clear')  # Linux and macOS

# Help command
  
def display_help():
    """Display custom help text."""
    help_command = (
        "\n"
        "USAGE:\n"
        "----------------------------------------------------------------------\n"
        "  • Enter one or more email addresses separated by commas to check their validity.\n"
        "  • For example: test@example.com, user@domain.com\n"
        "  • Results include a confidence score (0-100) and confidence level\n"
        "\n"        
        "AVAILABLE COMMANDS:\n"
        "----------------------------------------------------------------------\n"
        "  • 'help'      - Display this help message\n"
        "  • 'show log'  - Display a list of logged emails and their validation status\n"
        "  • 'clear log' - Delete all content from the log database\n"
        "  • 'clear'     - Clear the terminal window\n"
        "  • 'read more' - Learn more about features, functions, and use cases\n"
        "  • 'who am i'  - Display current user information\n"
        "  • 'exit'      - Quit the program\n"
        "\n"
        "CONFIDENCE LEVELS:\n"
        "----------------------------------------------------------------------\n"
        "  • Very High (90-100): Email almost certainly exists\n"
        "  • High (70-89): Email very likely exists\n"
        "  • Medium (50-69): Email probably exists\n"
        "  • Low (30-49): Email may exist but verification is uncertain\n"
        "  • Very Low (0-29): Email likely doesn't exist\n"
        "\n"
        "COLUMN CUSTOMIZATION:\n"
        "----------------------------------------------------------------------\n"
        "  • To change column visibility: Edit the 'show' value ('Y' or 'N') in config.py\n"
        "  • To change column order: Edit the 'index' value in config.py\n"
        "  • Lower index values appear first in the display\n"
    )
    print(help_command)

# Disposable email checking

def is_disposable_email(email):
    """Check if the email is from a disposable email provider."""
    domain = email.split('@')[1].lower()
    return domain in config.DISPOSABLE_DOMAINS

# Blacklist checking
def check_blacklists(email):
    """Check if the email's domain is blacklisted."""
    domain = email.split('@')[1].lower()
    if domain in config.BLACKLISTED_DOMAINS:
        return ", ".join(config.BLACKLISTED_DOMAINS[domain])
    else:
        return "Not Blacklisted"

# DNS Functions 

@ttl_cache(maxsize=1000, ttl=3600)  # Cache for 1 hour
def get_mx_record(domain: str) -> Optional[List[dns.resolver.Answer]]:
    """Cached MX record lookup with advanced error handling and fallback"""
    try:
        # Use explicit nameservers if configured
        resolver = dns.resolver.Resolver()
        if hasattr(config, 'DNS_SERVERS') and config.DNS_SERVERS:
            resolver.nameservers = config.DNS_SERVERS
            
        answers = resolver.resolve(domain, 'MX', lifetime=10)
        if answers:
            return sorted(answers, key=lambda x: x.preference)
        logger.warning(f"No MX records found for {domain}")
        return None
    except dns.resolver.NXDOMAIN:
        logger.warning(f"Domain {domain} does not exist")
        return None
    except dns.resolver.NoAnswer:
        logger.warning(f"No MX records for {domain}, trying A record as fallback")
        try:
            # Fallback to A record if no MX exists
            a_answers = resolver.resolve(domain, 'A', lifetime=10)
            if a_answers:
                # Create a fake MX record with the A record
                logger.info(f"Using A record as MX fallback for {domain}")
                class FakeMX:
                    def __init__(self, domain):
                        self.exchange = domain
                        self.preference = 10
                return [FakeMX(domain)]
        except Exception as e:
            logger.debug(f"A record fallback failed for {domain}: {e}")
        return None
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


# --- SMTP Connection Functions ---
@rate_limiter()  # Apply rate limiting to DNS lookups
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
                    logger.debug(f"SMTP connection successful for {email} on {server}:{port}")
                    return True
        except Exception as e:
            logger.debug(f"SMTP connection error on attempt {attempt + 1} for {server}:{port} - {e}")
            if attempt + 1 < retries:
                time.sleep(2)  # Increase sleep duration between retries
                continue
    logger.debug(f"SMTP connection failed after {retries} attempts for {email} on {server}:{port}")
    return False

# Apply rate limiting to SMTP VRFY function
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

#   SMTP Banner and MX IP Functions

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

#  Check Functions (IMAP/POP3)

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

def check_server_policies(domain: str) -> str:
    """Check if the domain has any specific anti-verification policies"""
    policies = []
    
    # Check for DMARC policy
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        for rdata in answers:
            if "v=DMARC1" in str(rdata):
                policies.append("DMARC")
                break
    except Exception as e:
        # Handle all DNS exceptions including NoNameservers
        logger.debug(f"DMARC policy check failed for {domain}: {e}")
    
    # Check for RFC 7208 (SPF) reject policies
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt = str(rdata)
            if "v=spf1" in txt and ("-all" in txt or "~all" in txt):
                policies.append("Strict SPF")
                break
    except Exception as e:
        # Handle all DNS exceptions
        logger.debug(f"SPF policy check failed for {domain}: {e}")
    
    # Check for explicit reject policies in TXT records
    if policies:
        return ", ".join(policies)
    else:
        return "None detected"

# --- Logging Functions ---

def log_exception(message, exception, show_to_user=True):
    """Centralized exception logging with optional user display"""
    logger.error(f"{message}: {str(exception)}")
    if show_to_user:
        print(f"Error: {message.lower()}")

def log_email_check(email, mx_record, spf_status, dkim_status, smtp_result, port, domain, **kwargs):
    """Log email verification results to database"""
    data = {
        'timestamp': datetime.now().strftime("%d-%m-%y %H:%M"),
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
        'pop3_banner': kwargs.get('pop3_banner', ''),
        'server_policies': check_server_policies(domain),
        'confidence_score': kwargs.get('confidence_score', 0),
        'execution_time': kwargs.get('execution_time', 0.0) 
    }
    
    try:
        server_policies = check_server_policies(domain)
    except Exception as e:
        logger.debug(f"Server policy check failed for {domain}: {e}")
        server_policies = "Check failed"
    
    # Remove extra whitespace from string values
    for key, value in data.items():
        if isinstance(value, str):
            data[key] = ' '.join(value.split())
    
    try:
        db = Database(config)
        db.log_check(data)
    except Exception as e:
        log_exception("Failed to log email check", e, show_to_user=False)

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

@performance_monitor
def validate_email(email, _start_time=None, **kwargs):
    """Enhanced email validation with confidence scoring"""
    logger.info(f"Starting validation for email: {email}")
    confidence_score = 0  # Initialize confidence score
    
    try:
        # Check email format
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            # Calculate execution time even for early returns
            execution_time = time.time() - _start_time if _start_time else 0.0
            
            log_email_check(email, "Invalid Format", "N/A", "N/A", "Invalid Email Format",
                          "N/A", "N/A", error_message="Invalid email format", 
                          blacklist_info=check_blacklists(email),
                          confidence_score=0,
                          execution_time=execution_time)  # Include execution time
            return "Invalid email format."
        else:
            confidence_score += 20  # Valid format gives 20 points
            
        domain = email.split('@')[1]
        disposable_status = "Disposable" if is_disposable_email(email) else "Not Disposable"
        
        # Penalize disposable emails
        if disposable_status == "Not Disposable":
            confidence_score += 10
        else:
            confidence_score -= 10
            
        logger.debug(f"Email {'is' if disposable_status == 'Disposable' else 'is not'} disposable, " 
                     f"{'subtracting 10 from' if disposable_status == 'Disposable' else 'adding 10 to'} "
                     f"confidence score (now {confidence_score})")
        
        blacklist_info = check_blacklists(email)
        
        # Penalize blacklisted domains
        if blacklist_info != "Not Blacklisted":
            confidence_score -= 15
        
        smtp_vrfy_result = ""
        catch_all_email = ""
        mx_preferences = ""
        smtp_banner = ""
        mx_ip = ""
        
        print(f"Checking MX records for {domain}...")
        logger.debug(f"Checking MX records for {domain}")
        mx_records = get_mx_record(domain)
        if not mx_records:
            # Calculate execution time even for early returns
            execution_time = time.time() - _start_time if _start_time else 0.0
            
            log_email_check(email, "No MX Records", "N/A", "N/A", "Could not verify email", "N/A", domain,
                          error_message="No MX records found", blacklist_info=blacklist_info, 
                          disposable_status=disposable_status, confidence_score=confidence_score,
                          execution_time=execution_time)  # Include execution time
            return "This domain cannot receive emails (no MX records)."
        else:
            confidence_score += 20  # Having valid MX records gives 20 points
            logger.debug(f"MX records found for {domain}, adding 20 to confidence score (now {confidence_score})")
        
        primary_mx = str(mx_records[0].exchange).rstrip('.')
        logger.debug(f"Primary MX for {domain} is {primary_mx}")
        print(f"Primary MX for {domain} is {primary_mx}.")
        
        spf_status = check_spf(domain)
        dkim_status = check_dkim(domain)
        
        # Add points for valid SPF and DKIM
        if spf_status == "SPF Found":
            confidence_score += 5
        if dkim_status == "DKIM Found":
            confidence_score += 5
            
        # Check for specific server policies
        policy_info = check_server_policies(domain) or "No specific policies detected"
        
        smtp_result = "Could not verify email"
        used_port = "N/A"
        error_message = ""
        
        # Port testing loop
        for port in config.PORTS_TO_TRY:
            logger.debug(f"Testing {domain} on port {port}...")
            print(f"Testing {domain} on port {port}...")
            if test_smtp_connection(primary_mx, port, email):
                smtp_result = "Email likely exists"
                used_port = port
                logger.info(f"Connection successful on port {port} for {email}")
                confidence_score += 30  # Successful SMTP connection adds 30 points
                break
                
        if smtp_result == "Email likely exists":
            fake_email = f"nonexistent{int(time.time())}@{domain}"
            if test_smtp_connection(primary_mx, used_port, fake_email):
                smtp_result = "Email likely exists"
                catch_all_email = fake_email
                logger.info(f"Catch-all detected for {domain} using {fake_email}")
                print(f"Catch-all detected: {fake_email} (email likely exists)")
                confidence_score -= 15  # Catch-all domains reduce confidence
            else:
                # No catch-all, higher confidence in result
                confidence_score += 15
        else:
            error_message = "SMTP check failed. Could not verify email."
            logger.info(f"SMTP verification failed for {email}")
        
        code, vrfy_msg = smtp_vrfy(primary_mx, used_port if used_port != "N/A" else 25, email)
        smtp_vrfy_result = "Verified" if code == 250 else "Not Verified"
        
        # Add points if VRFY command confirms the email
        if smtp_vrfy_result == "Verified":
            confidence_score += 10
            
        mx_preferences = ", ".join([str(mx.preference) for mx in mx_records])
        smtp_banner = get_smtp_banner(primary_mx)
        mx_ip = get_mx_ip(primary_mx)
        imap_status, imap_banner = check_imap_ssl(primary_mx)
        pop3_status, pop3_banner = check_pop3_ssl(primary_mx)
        
        # Add a few points if these services are available (more robust email system)
        if imap_status == "Available":
            confidence_score += 5
        if pop3_status == "Available":
            confidence_score += 5
        
        # Cap confidence between 0-100
        confidence_score = max(0, min(100, confidence_score))
        
        # Get confidence level label
        confidence_level = get_confidence_level(confidence_score)
        
        # Update the result message with confidence information
        result_with_confidence = f"{smtp_result} (Confidence: {confidence_level}, {confidence_score}/100)"
        
        # At the end, calculate the execution time ONCE
        if _start_time is not None:
            execution_time = time.time() - _start_time
        else:
            # Fallback if somehow _start_time wasn't passed
            execution_time = 0.0
            logger.warning(f"Missing _start_time for {email}, unable to calculate execution time")
        
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
            pop3_banner=pop3_banner,
            server_policies=policy_info,
            confidence_score=confidence_score,
            execution_time=execution_time  # Use the calculated execution time
        )
        
        logger.info(f"Validation complete for {email}: confidence score is {confidence_score}/100 ({get_confidence_level(confidence_score)})")
        return result_with_confidence
    except Exception as e:
        # Calculate execution time even for exceptions
        execution_time = time.time() - _start_time if _start_time else 0.0
        
        logger.error(f"Error validating {email}: {str(e)}", exc_info=True)
        
        # Log the error with execution time
        log_email_check(email, "Error", "N/A", "N/A", "Validation Error", "N/A", 
                      email.split('@')[1] if '@' in email else "unknown",
                      error_message=str(e),
                      execution_time=execution_time)
        raise

def validate_emails(emails):
    """Validate multiple email addresses in parallel with optimized concurrency."""
    worker_count = min(len(emails), config.MAX_WORKER_THREADS, os.cpu_count() * 2 or 5)
    
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        chunk_size = max(1, len(emails) // worker_count)
        futures = [executor.submit(validate_email, email) for email in emails]
        return [future.result() for future in as_completed(futures)]

# --- Show log---   
def load_selected_columns():
    """Load column display settings from config"""
    selected_columns = {}
    
    # Get visible columns directly from config
    visible_columns = config.get_visible_columns()
    
    # Use the original column keys, not the name attribute
    for key, column in visible_columns.items():
        selected_columns[key] = column.index
    
    return selected_columns

def display_logs():
    """Display all email verification logs"""
    try:
        global db
        
        # Get columns to display from config
        selected_columns = load_selected_columns()
        
        # Simple database connection without authentication
        logger.debug("Initializing new database connection for log display")
        db = Database(config)
            
        # Pass the selected columns to show_logs
        logger.debug("Fetching logs from database")
        columns, rows = db.show_logs(selected_columns)
        
        if not rows:
            print("\nNo log entries found.")
            return
        
        # Display formatted data
        print("\nEmail Verification Logs:")
        print(tabulate(
            rows,
            headers=columns,
            tablefmt='grid',
            numalign='left',
            stralign='left'
        ))
        print()
        
    except Exception as e:
        log_exception("Error displaying logs", e)
      
def clear_log():
    """Clear the email logs table and reset sequence counter"""
    try:
        # Simple confirmation
        confirmation = input("\nAre you sure you want to clear all email logs? This cannot be undone. (yes/no): ")
        
        if confirmation.lower() == 'yes':
            db.clear_logs() # Clear all logs
            db.reset_sequence("email_logs")  # Reset sequence counter
            print("\nAll logs have been cleared successfully.")
        else:
            print("\nLog clearing cancelled.")
            
    except Exception as e:
        log_exception("Error clearing logs", e)

def toggle_column(column_name):
    """Toggle visibility of a specific column"""
    if config.toggle_column_visibility(column_name):
        print(f"Column '{column_name}' visibility toggled successfully.")
        # Show current visibility
        visible = config.LOG_COLUMNS[column_name].show == 'Y'
        status = "visible" if visible else "hidden"
        print(f"Column '{column_name}' is now {status}.")
    else:
        print(f"Column '{column_name}' not found.")

# --- Main Loop ---
def main():
    """Main entry point"""
    try:
        logger.info("Application starting")
        global db
        db = Database(config)
        
        WELCOME_BANNER = (
    "======================================================================\n"
    "Email Verification Script - Version 1.0\n"
    "Copyright (C) 2025 Kim Skov Rasmussen\n"
    "Licensed under GNU General Public License v3.0\n"  
    "This software is provided as is, without any warranties.\n"  
    "Use at your own risk. For educational purposes only.\n"
    "\n"
    "Type 'help' to see available commands.\n"
    "======================================================================\n"
        )
        
        # Clear screen and show welcome banner
        clear_screen()
        print(WELCOME_BANNER)
        logger.debug("Entering main command loop")
               
        # Main command loop
        while True:
            try:
                user_input = input("\nCommand> ").strip()
                if not user_input:
                    continue
                
                # Handle commands
                if user_input.lower() == "exit":
                    logger.info("User initiated program exit")
                    clear_screen()
                    print("Exiting program.")
                    break

                elif user_input.lower() == "help":
                    display_help()
                    continue

                elif user_input.lower() == "show log":
                    display_logs()
                    continue

                elif user_input.lower() == "read more":
                    file_path = os.path.join(os.getcwd(), "README.md")
                    webbrowser.open(file_path)
                    continue
                    
                elif user_input.lower() == "clear log":
                    clear_log()
                    continue
                    
                elif user_input.lower() == "clear":
                    clear_screen()
                    continue

                elif user_input.lower() == "who am i":
                    print(
                    "\n""- \033[3mHe yells this out in frustration,\n"
                    "  and confusion as he tries to uncover his identity.\033[0m \n"
                    "\n"
                    "USER INFORMATION: \n"
                    "======================================================================"
                    )
                    print(f"Name       : {config.USER_CREDENTIALS.USER_NAME}")
                    print(f"E-mail     : {config.USER_CREDENTIALS.USER_EMAIL}")
                    print(f"Created at : {config.USER_CREDENTIALS.USER_CREATION_TIME}")
                    continue

                # Split input by commas and remove empty spaces
                emails = [email.strip() for email in user_input.split(",") if email.strip()]

                # Check if the input contains valid email(s)
                if all(re.match(r"[^@]+@[^@]+\.[^@]+", email) for email in emails):
                    logger.info(f"Processing email validation for: {', '.join(emails)}")
                    results = validate_emails(emails)
                    for email, result in zip(emails, results):
                        print(f"{email}: {result}\n")
                    continue  # Skip "Unknown command" check

                # If input is neither a known command nor a valid email, show an error
                logger.debug(f"Unknown command: {user_input}")
                print("Unknown command. Type 'help' for available commands.")
                    
            except KeyboardInterrupt:
                logger.debug("KeyboardInterrupt received")
                print("\nUse 'exit' to quit.")
            except Exception as e:
                log_exception("Command error", e)
    
    except Exception as e:
        log_exception("Application error", e)
        sys.exit(1)
    finally:
        logger.info("Application exiting")

class SMTPConnectionPool:
    """Improved SMTP Connection Pool with connection reuse by server"""
    def __init__(self, max_connections=10):
        self.pool = {}
        self.max_per_server = max_connections
        self.lock = threading.RLock()
        logger.debug(f"Initialized SMTP connection pool with capacity {max_connections}")

    @contextmanager
    def get_connection(self, host, port):
        server_key = f"{host}:{port}"
        
        with self.lock:
            if server_key not in self.pool:
                self.pool[server_key] = []
            
            if self.pool[server_key]:
                smtp = self.pool[server_key].pop()
                reused = True
            else:
                smtp = smtplib.SMTP(timeout=10)
                reused = False
        
        try:
            if not reused or not smtp.sock:
                logger.debug(f"{'Reusing' if reused else 'Creating new'} SMTP connection to {host}:{port}")
                smtp.connect(host, port)
                smtp.ehlo() 
            yield smtp
        finally:
            with self.lock:
                if len(self.pool[server_key]) < self.max_per_server:
                    self.pool[server_key].append(smtp)
                    logger.debug(f"Returned SMTP connection to pool for {server_key}")
                else:
                    try:
                        smtp.quit()
                    except:
                        pass
                    logger.debug(f"Pool for {server_key} full, closed connection")

@contextmanager
def safe_smtp_connection(server, port):
    """Safe SMTP connection context manager with proper resource cleanup"""
    smtp = None
    try:
        smtp = smtplib.SMTP(timeout=10)
        smtp.connect(server, port)
        yield smtp
    except Exception as e:
        logger.error(f"SMTP connection error: {e}")
        raise
    finally:
        if smtp:
            try:
                smtp.quit()
            except Exception:
                pass 

# Create global connection pool
smtp_pool = SMTPConnectionPool(max_connections=config.CONNECTION_POOL_SIZE)

# Initialize database connection
db = None  # Will be initialized in main()

def get_confidence_level(score):
    """Convert numerical score to confidence level description"""
    if score >= 90:
        return "Very High"
    elif score >= 70:
        return "High"
    elif score >= 50:
        return "Medium"
    elif score >= 30:
        return "Low"
    else:
        return "Very Low"

if __name__ == "__main__":
    main()
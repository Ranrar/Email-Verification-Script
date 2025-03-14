#!/usr/bin/env python3
# Email Verification Script
# Copyright (C) 2025 Kim Skov Rasmussen
#
# This work is licensed under the Creative Commons Attribution-NonCommercial-NoDerivatives 4.0 International License.
#
# You are free to use this software for academic research purposes only. However, you may not:
#
#    Use this software for commercial purposes.
#    Alter, transform, or build upon this work in any way (i.e., No Derivatives).
#    Redistribute this software or any modified versions of it without explicit permission from the author.
#
# Any redistribution, modification, or commercial use of this software is prohibited unless you have received explicit permission from the author.

import sys
import subprocess
import time
import os
import platform
import socket
import dns.resolver
import smtplib
import re
import imaplib
import poplib
import webbrowser
import threading
from packages.installer import Installer
from collections import deque
from contextlib import contextmanager
from datetime import datetime, timedelta
from functools import wraps
from tabulate import tabulate
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, List
from packages.logger.logger import P_Log
from config import config

# Get configuration singleton instance
cfg = config()

# Initialize logger early
logger = P_Log(logger_name='evs', log_to_console=False)

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


# Define these variables before using them
smtp_pool = None

# Global variables initialization
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
def ttl_cache(cache_name='mx_record'):
    """Universal time-based cache decorator with maximum size limit
    
    Args:
        cache_name: Name of the cache configuration to use from settings
                   (mx_record, ttl_cache, etc.)
    """
    def decorator(func):
        cache = {}
        timestamps = {}
        last_cleanup = datetime.now()
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            nonlocal last_cleanup
            
            # Get cache settings from database based on cache_name
            try:
                # Get the specific named cache configuration
                cache_config = getattr(cfg.cache_setting, cache_name)
                
                # Use the values from the database
                maxsize = cache_config['max_size']
                ttl = cache_config['ttl_seconds']
                cleanup_interval = cache_config['cleanup_interval']
                
            except Exception as e:
                # Log the error but don't provide fallbacks - require proper configuration
                logger.error(f"Error loading cache config for '{cache_name}': {e}")
                # Re-raise the exception to indicate configuration is required
                raise ValueError(f"Cache configuration '{cache_name}' is missing or invalid") from e
            
            # Create a unique key for the cache based on function args
            def make_key(*args, **kwargs):
                """Create a more efficient cache key"""
                key_parts = [repr(arg) for arg in args]
                key_parts.extend(f"{k}:{repr(v)}" for k, v in sorted(kwargs.items()))
                return hash(tuple(key_parts))
            
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
                logger.debug(f"Cache cleanup for {func.__name__} ({cache_name}): removed {len(expired_keys)} expired entries")
            
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

# chek blacklisted and disposable domains
def is_disposable_email(email):
    """Check if the email is from a disposable email provider."""
    domain = email.split('@')[1].lower()
    return cfg.disposable_domain.is_disposable(domain)

def check_blacklists(email):
    """Check if the email's domain is blacklisted."""
    domain = email.split('@')[1].lower()
    is_blacklisted, blacklist_sources = cfg.blacklisted_domain.is_blacklisted(domain)
    
    if is_blacklisted and blacklist_sources:
        return ", ".join(blacklist_sources)
    else:
        return "Not Blacklisted"

# clearer screen function
def clear_screen():
    if platform.system() == "Windows":
        os.system('cls')  # Windows
    else:
        os.system('clear')  # Linux and macOS

# Help command
def display_help():
    """Display comprehensive help information for the Email Verification Script."""
    help_text = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                       EMAIL VERIFICATION SCRIPT HELP                         ║
╚══════════════════════════════════════════════════════════════════════════════╝

▶ BASIC USAGE
  Simply enter one or more email addresses separated by commas to verify them:
  example@domain.com, test@example.org

▶ AVAILABLE COMMANDS
  help        Display this help information
  show log    Display email validation history with results
  clear log   Delete all validation history from the database
  clear       Clear the terminal screen
  read more   Open the detailed documentation in your browser
  who am i    Display current user information
  exit        Quit the application

▶ VALIDATION INFORMATION
  Each validation provides:
  • MX record verification (checks if domain can receive email)
  • SMTP connection testing (verifies mailbox existence)
  • Catch-all detection (identifies domains accepting all emails)
  • SPF and DKIM record checking (email security verification)
  • Disposable email detection (identifies temporary email services)
  • Blacklist checking (identifies potentially problematic domains)
  • IMAP/POP3 availability (additional mail server information)

▶ CONFIDENCE SCORING
  Each validation includes a confidence score (0-100) with levels:
  • Very High (90-100) - Email almost certainly exists
  • High     (70-89)  - Email very likely exists
  • Medium   (50-69)  - Email probably exists
  • Low      (30-49)  - Email may exist but verification is uncertain
  • Very Low (0-29)   - Email likely doesn't exist

▶ ADVANCED FEATURES
  • debug log    Show raw database records for debugging
  • refresh      Refresh database connection and clear cache
"""
    print(help_text)

# DNS Functions and Utilities
def rate_limiter(operation_name=None):
    """Rate limiter using sliding window with database configuration."""
    def decorator(func):
        requests = deque()
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            nonlocal requests
            
            # Get rate limit settings from database
            rate_limit_config = None
            try:
                # Access the rate_limit attributes directly instead of using get()
                if operation_name:
                    # Use getattr to safely access attributes
                    if hasattr(cfg.rate_limit, operation_name):
                        rate_limit_config = getattr(cfg.rate_limit, operation_name)
            except Exception as e:
                logger.warning(f"Failed to get rate limit config for {operation_name}: {e}")
            
            # If not found, use defaults from app settings with proper fallbacks
            if not rate_limit_config:
                default_max_requests = cfg.app_setting.get('rate_limiter', 'rate_limit_requests', 10)
                default_time_window = cfg.app_setting.get('rate_limiter', 'rate_limit_window', 60)
                rate_limit_config = {
                    'max_requests': default_max_requests,
                    'time_window': default_time_window
                }
            
            max_requests = rate_limit_config['max_requests']
            time_window = rate_limit_config['time_window']
            
            # Set max length for the deque
            if len(requests) == 0 or requests.maxlen != max_requests:
                # Create a new deque with the correct maxlen
                old_requests = list(requests)
                requests = deque(old_requests, maxlen=max_requests)
            
            now = time.time()
            
            # Remove old requests
            while requests and now - requests[0] > time_window:
                requests.popleft()
                
            # Check if we've hit the limit
            if len(requests) >= max_requests:
                wait_time = requests[0] + time_window - now
                if wait_time > 0:
                    logger.warning(f"Rate limit reached for {operation_name or func.__name__}. Waiting {wait_time:.2f} seconds...")
                    time.sleep(wait_time)
            
            result = func(*args, **kwargs)
            requests.append(now)
            return result
        return wrapper
    return decorator

@rate_limiter(operation_name='dns_lookup')
@ttl_cache('mx_record')
def get_mx_record(domain: str) -> Optional[List[dns.resolver.Answer]]:
    """Cached MX record lookup with advanced error handling and fallback"""
    try:
        # Use explicit nameservers if configured
        resolver = dns.resolver.Resolver()
        nameservers = cfg.dns_setting.nameservers
        if nameservers:
            # If stored as a comma-separated string, split it
            if isinstance(nameservers, str):
                resolver.nameservers = [s.strip() for s in nameservers.split(',')]
            else:
                resolver.nameservers = nameservers
            
        # Get timeout from config
        lifetime = cfg.dns_setting.timeout
        
        answers = resolver.resolve(domain, 'MX', lifetime=lifetime)
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
            # Check if A record fallback is enabled in config
            use_a_fallback = cfg.dns_setting.use_a_record_fallback
            if use_a_fallback:
                # Fallback to A record if no MX exists
                a_answers = resolver.resolve(domain, 'A', lifetime=lifetime)
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

@ttl_cache('ttl_cache')
@rate_limiter(operation_name='dns_lookup')
def check_spf(domain):
    """Check for SPF record in domain's TXT records."""
    try:
        # Use the same resolver configuration as get_mx_record
        resolver = dns.resolver.Resolver()
        nameservers = cfg.dns_setting.nameservers
        if nameservers:
            if isinstance(nameservers, str):
                resolver.nameservers = [s.strip() for s in nameservers.split(',')]
            else:
                resolver.nameservers = nameservers
                
        lifetime = cfg.dns_setting.timeout
        
        answers = resolver.resolve(domain, 'TXT', lifetime=lifetime)
        for rdata in answers:
            if "v=spf1" in str(rdata):
                return "SPF Found"
        return "No SPF Record"
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return "No SPF Record"
    except Exception as e:
        logger.debug(f"SPF check failed for {domain}: {e}")
        return "SPF Check Error"

@ttl_cache('ttl_cache')
@rate_limiter(operation_name='dns_lookup')
def check_dkim(domain):
    """Check for DKIM TXT record in domain's DNS settings."""
    try:
        # Use the same resolver configuration as get_mx_record
        resolver = dns.resolver.Resolver()
        nameservers = cfg.dns_setting.nameservers
        if nameservers:
            if isinstance(nameservers, str):
                resolver.nameservers = [s.strip() for s in nameservers.split(',')]
            else:
                resolver.nameservers = nameservers
                
        lifetime = cfg.dns_setting.timeout
        
        # Get DKIM selector from config
        dkim_selector = cfg.dns_setting.dkim_selector
        dkim_domain = f"{dkim_selector}._domainkey.{domain}"
        
        answers = resolver.resolve(dkim_domain, 'TXT', lifetime=lifetime)
        for rdata in answers:
            if "v=DKIM1" in str(rdata):
                return "DKIM Found"
        return "No DKIM Record"
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return "No DKIM Record"
    except Exception as e:
        logger.debug(f"DKIM check failed for {domain}: {e}")
        return "DKIM Check Error"

@rate_limiter(operation_name='dns_lookup')
def get_mx_ip(server):
    """Get the IP address of the MX server."""
    timeout = cfg.dns_setting.timeout
    
    try:
        socket.setdefaulttimeout(timeout)
        ip = socket.gethostbyname(server)
        return ip
    except socket.gaierror:
        return "Unknown IP"
    finally:
        socket.setdefaulttimeout(None)  # Reset timeout


# --- SMTP Connection Functions ---
@rate_limiter(operation_name='smtp_connection')
def test_smtp_connection(server, port, email):
    """Test SMTP connection to a server using database configuration"""
    # Get settings from database via config
    retries = cfg.smtp_setting.max_retries
    timeout = cfg.smtp_setting.timeout
    retry_delay = cfg.smtp_setting.retry_delay
    test_sender = cfg.smtp_setting.test_sender
    
    for attempt in range(retries):
        try:
            with smtplib.SMTP(server, port, timeout=timeout) as smtp:
                smtp.ehlo()
                smtp.mail(test_sender)
                code, _ = smtp.rcpt(email)
                if code == 250:
                    logger.debug(f"SMTP connection successful for {email} on {server}:{port}")
                    return True
        except Exception as e:
            logger.debug(f"SMTP connection error on attempt {attempt + 1} for {server}:{port} - {e}")
            if attempt + 1 < retries:
                time.sleep(retry_delay)
                continue
    logger.debug(f"SMTP connection failed after {retries} attempts for {email} on {server}:{port}")
    return False

@rate_limiter(operation_name='smtp_vrfy')
def smtp_vrfy(server, port, email):
    """Attempt SMTP VRFY command to check if the email exists."""
    timeout = cfg.smtp_setting.timeout
        
    try:
        with smtplib.SMTP(server, port, timeout=timeout) as smtp:
            smtp.ehlo()
            code, msg = smtp.verify(email)
            if isinstance(msg, bytes):
                msg = msg.decode()
            return code, msg
    except Exception as e:
        return None, str(e)

def get_smtp_banner(server):
    """Get the SMTP banner by trying HELLO and then EHLO commands, removing newlines."""
    timeout = cfg.smtp_setting.timeout
    hello_command = cfg.smtp_setting.hello_command
    
    try:
        with smtplib.SMTP(server, timeout=timeout) as smtp:
            banner = smtp.docmd(hello_command)
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
    timeout = cfg.dns_setting.timeout
    
    try:
        socket.setdefaulttimeout(timeout)
        ip = socket.gethostbyname(server)
        return ip
    except socket.gaierror:
        return "Unknown IP"
    finally:
        socket.setdefaulttimeout(None)

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
        'timestamp': datetime.now(),
        'email': email,
        'domain': domain,
        'smtp_result': smtp_result,
        'mx_record': mx_record,
        'port': port,
        'disposable': kwargs.get('disposable_status', ''),
        'spf_status': spf_status,
        'dkim_status': dkim_status,
        'catch_all': kwargs.get('catch_all_email', ''),
        'blacklist_info': kwargs.get('blacklist_info', ''),
        'mx_preferences': kwargs.get('mx_preferences', ''),
        'smtp_banner': kwargs.get('smtp_banner', ''),
        'mx_ip': kwargs.get('mx_ip', ''),
        'error_message': kwargs.get('error_message', ''),
        'imap_status': kwargs.get('imap_status', ''),
        'imap_banner': kwargs.get('imap_banner', ''),
        'pop3_status': kwargs.get('pop3_status', ''),
        'pop3_banner': kwargs.get('pop3_banner', ''),
        'server_policies': kwargs.get('server_policies', ''),
        'confidence_score': kwargs.get('confidence_score', 0),
        'execution_time': kwargs.get('execution_time', 0.0) 
    }
    
    # Remove extra whitespace from string values
    for key, value in data.items():
        if isinstance(value, str):
            data[key] = ' '.join(value.split())
    
    try:
        with cfg.connect() as conn:
            cursor = conn.cursor()
            
            # Check if this email already exists in the database
            cursor.execute("SELECT id, check_count FROM email_validation_records WHERE email = ? ORDER BY timestamp DESC LIMIT 1", (email,))
            existing_record = cursor.fetchone()
            
            if existing_record:
                # Email already exists, update the record and increment check_count
                record_id = existing_record['id']
                check_count = existing_record['check_count'] + 1 if existing_record['check_count'] else 1
                
                # UPDATE SQL statement
                cursor.execute("""
                    UPDATE email_validation_records SET
                    timestamp = ?, smtp_result = ?, mx_record = ?, port = ?, disposable = ?, 
                    spf_status = ?, dkim_status = ?, catch_all = ?, blacklist_info = ?,
                    mx_preferences = ?, smtp_banner = ?, mx_ip = ?, error_message = ?,
                    imap_status = ?, imap_info = ?, pop3_status = ?, pop3_info = ?, 
                    server_policies = ?, confidence_score = ?, execution_time = ?, check_count = ?
                    WHERE id = ?
                """, (
                    data['timestamp'], data['smtp_result'], data['mx_record'], data['port'],
                    data['disposable'], data['spf_status'], data['dkim_status'], data['catch_all'], 
                    data['blacklist_info'], data['mx_preferences'], data['smtp_banner'], data['mx_ip'],
                    data['error_message'], data['imap_status'], data['imap_banner'], data['pop3_status'], 
                    data['pop3_banner'], data['server_policies'], data['confidence_score'], data['execution_time'],
                    check_count, record_id
                ))
                logger.debug(f"Updated existing record for {email} (check count: {check_count})")
            else:
                # First time checking this email, insert a new record
                cursor.execute("""
                    INSERT INTO email_validation_records (
                        timestamp, email, domain, smtp_result, mx_record, port, disposable, spf_status, dkim_status,
                        catch_all, blacklist_info, mx_preferences, smtp_banner, mx_ip,
                        error_message, imap_status, imap_info, pop3_status, pop3_info, server_policies,
                        confidence_score, execution_time, check_count
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                """, (
                    data['timestamp'], data['email'], data['domain'], data['smtp_result'], data['mx_record'], data['port'],
                    data['disposable'], data['spf_status'], data['dkim_status'], data['catch_all'], 
                    data['blacklist_info'], data['mx_preferences'], data['smtp_banner'], data['mx_ip'],
                    data['error_message'], data['imap_status'], data['imap_banner'], data['pop3_status'], 
                    data['pop3_banner'], data['server_policies'], data['confidence_score'], data['execution_time']
                ))
                logger.debug(f"Created new record for {email}")
            
            conn.commit()
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
    confidence_score = 0

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
            confidence_score += cfg.validation_scoring.valid_format  # Use config instead of hardcoded 20
            
        domain = email.split('@')[1]
        disposable_status = "Disposable" if is_disposable_email(email) else "Not Disposable"
        
        # Penalize disposable emails
        if disposable_status == "Not Disposable":
            confidence_score += cfg.validation_scoring.not_disposable  # Instead of hardcoded 10
        else:
            confidence_score += cfg.validation_scoring.disposable  # This will be negative from the database
            
        logger.debug(f"Email {'is' if disposable_status == 'Disposable' else 'is not'} disposable, " 
                     f"{'subtracting 10 from' if disposable_status == 'Disposable' else 'adding 10 to'} "
                     f"confidence score (now {confidence_score})")
        
        blacklist_info = check_blacklists(email)
        
        # Penalize blacklisted domains
        if blacklist_info != "Not Blacklisted":
            confidence_score += cfg.validation_scoring.blacklisted  # Will be negative
        
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
            confidence_score += cfg.validation_scoring.mx_records  # Instead of hardcoded 20
            logger.debug(f"MX records found for {domain}, adding 20 to confidence score (now {confidence_score})")
        
        primary_mx = str(mx_records[0].exchange).rstrip('.')
        logger.debug(f"Primary MX for {domain} is {primary_mx}")
        print(f"Primary MX for {domain} is {primary_mx}.")
        
        spf_status = check_spf(domain)
        dkim_status = check_dkim(domain)
        
        # Add points for valid SPF and DKIM
        if spf_status == "SPF Found":
            confidence_score += cfg.validation_scoring.spf_found
        if dkim_status == "DKIM Found":
            confidence_score += cfg.validation_scoring.dkim_found
            
        # Check for specific server policies
        policy_info = check_server_policies(domain) or "No specific policies detected"
        
        smtp_result = "Could not verify email"
        used_port = "N/A"
        error_message = ""
        
        # Port testing loop
        for port in cfg.smtp_ports.get_all():
            logger.debug(f"Testing {domain} on port {port}...")
            print(f"Testing {domain} on port {port}...")
            if test_smtp_connection(primary_mx, port, email):
                smtp_result = "Email likely exists"
                used_port = port
                logger.info(f"Connection successful on port {port} for {email}")
                confidence_score += cfg.validation_scoring.smtp_connection  # Successful SMTP connection adds 30 points
                break
                
        if smtp_result == "Email likely exists":
            fake_email = f"nonexistent{int(time.time())}@{domain}"
            if test_smtp_connection(primary_mx, used_port, fake_email):
                smtp_result = "Email likely exists"
                catch_all_email = fake_email
                logger.info(f"Catch-all detected for {domain} using {fake_email}")
                print(f"Catch-all detected: {fake_email} (email likely exists)")
                confidence_score += cfg.validation_scoring.catch_all  # Catch-all domains reduce confidence
            else:
                # No catch-all, higher confidence in result
                confidence_score += cfg.validation_scoring.no_catch_all
        else:
            error_message = "SMTP check failed. Could not verify email."
            logger.info(f"SMTP verification failed for {email}")
        
        code, vrfy_msg = smtp_vrfy(primary_mx, used_port if used_port != "N/A" else 25, email)
        smtp_vrfy_result = "Verified" if code == 250 else "Not Verified"
        
        # Add points if VRFY command confirms the email
        if smtp_vrfy_result == "Verified":
            confidence_score += cfg.validation_scoring.smtp_vrfy
            
        mx_preferences = ", ".join([str(mx.preference) for mx in mx_records])
        smtp_banner = get_smtp_banner(primary_mx)
        mx_ip = get_mx_ip(primary_mx)
        imap_status, imap_banner = check_imap_ssl(primary_mx)
        pop3_status, pop3_banner = check_pop3_ssl(primary_mx)
        
        # Add a few points if these services are available (more robust email system)
        if imap_status == "Available":
            confidence_score += cfg.validation_scoring.imap_available
        if pop3_status == "Available":
            confidence_score += cfg.validation_scoring.pop3_available
        
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
            execution_time=execution_time  
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
    worker_count = min(len(emails), cfg.thread_pool_setting.max_worker_threads, (os.cpu_count() * 2 or 5))

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        chunk_size = max(1, len(emails) // worker_count)
        futures = [executor.submit(validate_email, email) for email in emails]
        return [future.result() for future in as_completed(futures)]

# --- Show log---   
def load_selected_columns():
    """Load column display settings from config"""
    return cfg.get_column_settings()

def display_logs():
    """Display all email verification logs from email_validation_records"""
    try:
        # Get list of actual columns from the table
        logger.debug("Loading column display settings")
        
        # First, get visible columns with proper ordering from email_records_field_definitions
        with cfg.connect() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT name, display_name 
                FROM email_records_field_definitions 
                WHERE visible = 1
                ORDER BY display_index asc
            """)
            display_settings = cursor.fetchall()
            
            if not display_settings:
                print("\nNo column display settings found in database.")
                return
        
        # Create a mapping of database column names to display names
        # And build a list of columns in the correct display order
        column_map = {}
        actual_columns = []
        
        # Get actual table schema to verify columns exist
        with cfg.connect() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(email_validation_records)")
            table_info = cursor.fetchall()
            db_columns = [row['name'] for row in table_info]
        
        # Map definition names to actual column names and keep only existing columns
        for setting in display_settings:
            col_name = setting['name']  # Column name as defined in field definitions
            display_name = setting['display_name']
            
            # Check if this column actually exists in the table
            if col_name in db_columns:
                column_map[col_name] = display_name
                actual_columns.append(col_name)
            else:
                logger.warning(f"Column '{col_name}' from definitions not found in actual table")
        
        if not actual_columns:
            print("\nNo matching columns found between definitions and the actual table.")
            return
        
        # First, check if there are any records at all
        with cfg.connect() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) AS count FROM email_validation_records")
            count = cursor.fetchone()['count']
            
        if count == 0:
            print("\nNo email validation logs found in the database.")
            logger.info("No email validation records found in the database.")
            return
        
        # Fetch logs from database with limit from app settings
        display_limit = cfg.app_setting.get('general', 'log_display_limit', 50)
        logger.debug(f"Fetching up to {display_limit} logs from database")
        
        # Build the query dynamically based on the actual columns
        with cfg.connect() as conn:
            cursor = conn.cursor()
            query = f"SELECT {', '.join(actual_columns)} FROM email_validation_records ORDER BY timestamp ASC LIMIT ?"
            cursor.execute(query, (display_limit,))
            records = cursor.fetchall()
        
        if not records:
            print("\nNo email validation records found.")
            return
        
        # Prepare headers and rows for tabulation
        headers = [column_map.get(col, col.capitalize()) for col in actual_columns]
        rows = []
        
        # Debug information
        logger.debug(f"Records fetched: {len(records)}")
        logger.debug(f"Headers: {headers}")
        
        for record in records:
            row = []
            for col in actual_columns:
                # Get the value, with proper None handling
                value = record[col]
                
                # Format datetime values nicely
                if col == "timestamp" and value:
                    try:
                        dt = datetime.fromisoformat(value)
                        value = dt.strftime("%d-%m-%y %H:%M")
                    except:
                        pass
                        
                # Format confidence score with level
                if col == "confidence_score" and value is not None:
                    try:
                        confidence_level = cfg.confidence_level.get_level_for_score(value)
                        if confidence_level:
                            value = f"{value} ({confidence_level})"
                        else:
                            value = str(value)
                    except Exception as e:
                        logger.warning(f"Error formatting confidence level: {e}")
                        value = str(value)
                        
                # Ensure we have a string value
                if value is None:
                    value = ""
                elif not isinstance(value, str):
                    value = str(value)
                    
                # Truncate long values
                if isinstance(value, str) and len(value) > 30:
                    value = value[:27] + "..."
                    
                row.append(value)
            rows.append(row)
        
        # Display formatted data
        print("\nEmail Validation Logs:")
        print(tabulate(
            rows,
            headers=headers,
            tablefmt='grid',
            numalign='left',
            stralign='left'
        ))
        print(f"\nShowing {len(records)} of {display_limit} maximum records.")
        
    except Exception as e:
        log_exception("Error displaying logs", e)

def clear_log():
    """Clear the email logs table and reset sequence counter"""
    try:
        # Simple confirmation
        confirmation = input("\nAre you sure you want to clear all email logs? This cannot be undone. (yes/no): ")
        
        if confirmation.lower() == 'yes':
            conn = cfg.connect()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM email_validation_records")
            cursor.execute("DELETE FROM sqlite_sequence WHERE name='email_validation_records'")
            conn.commit()
            conn.close()
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

def debug_show_records():
    """Simple debug function to see what's in the table"""
    try:
        with cfg.connect() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM email_validation_records LIMIT 5")
            records = cursor.fetchall()
            
            for record in records:
                print(record.keys())  # Show all column names
                print(dict(record))   # Show all values
                print("---")
    except Exception as e:
        print(f"Error: {e}")

# --- Main Loop ---
def main():
    """Main entry point"""
    try:
        logger.info("Application starting")
        
        # Simple initialization
        if not initialize_system():
            print("Failed to initialize system. Exiting.")
            return 1
        
        # Continue with the rest of your main function...
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

                # debug command to chek the database connection 
                elif user_input.lower() == "refresh":
                    cfg.refresh_db_state()
                    logger.debug("refreshing the database connection and clearing the cache.")
                    print("refreshing the database connection and clearing the cache")
                    continue

                # debug command to chek the database connection
                elif user_input.lower() == "debug log":
                    debug_show_records()
                    logger.debug("debugging the database connection.")
                    print("debugging the database connection")
                    continue

                elif user_input.lower() == "who am i":
                    user_info = cfg.get_active_user()
                    print(
                    "\n""- \033[3mHe yells this out in frustration,\n"
                    "  and confusion as he tries to uncover his identity.\033[0m \n"
                    "\n"
                    "USER INFORMATION: \n"
                    "======================================================================"
                    )
                    print(f"Name       : {user_info['name']}")
                    print(f"E-mail     : {user_info['email']}")
                    print(f"Created at : {user_info['created_at']}")
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
            if (server_key not in self.pool):
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

def get_confidence_level(score):
    """Get confidence level based on score using config"""
    return cfg.confidence_level.get_level_for_score(score)

def initialize_system():
    """Initialize the system and core components"""
    try:
        logger.info("Initializing system...")
        
        # Check if database directory exists
        db_dir = os.path.join(os.getcwd(), 'DB')
        db_path = os.path.join(db_dir, 'EVS.db')
        
        # Check if database file exists
        if not os.path.exists(db_path):
            logger.info("Database file missing, running installer...")
            
            # Call the installer from packages
            installer = Installer()
            if not installer.run_installation():
                logger.error("Installation failed")
                print("Installation failed. Please check logs for details.")
                print(f"Log file location: {os.path.join(os.getcwd(), 'logs')}")
                input("\nPress Enter to exit...")  # Give user time to read the message
                return False
                
            logger.info("First-time setup completed successfully")
            print("First-time setup completed successfully!")
            # Add a pause to let the user read the message
            input("\nPress Enter to continue...")
        else:
            logger.info("Using existing database")
            
        # Initialize global database connection
        global db
        logger.info("Database connection established")
        
        # Initialize global SMTP connection pool
        global smtp_pool
        pool_size = 5  # Default value
        try:
            if cfg.smtp_setting.pool_size is not None:
                pool_size = cfg.smtp_setting.pool_size
        except Exception as e:
            logger.warning(f"Could not get SMTP pool size, using default: {e}")
        
        smtp_pool = SMTPConnectionPool(max_connections=pool_size)
        logger.debug(f"Initialized SMTP connection pool with capacity {pool_size}")
        logger.info("SMTP connection pool initialized")
        
        return True
    except Exception as e:
        log_exception("Failed to initialize system", e)
        return False
    
if __name__ == "__main__":
    main()
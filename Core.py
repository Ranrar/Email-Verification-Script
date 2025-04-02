import time
import os
import platform
import socket
import dns.resolver
import smtplib
import re
import imaplib
import poplib
import threading
import csv
import json
from packages.installer.Installer import Installer
from collections import deque
from contextlib import contextmanager
from datetime import datetime, timedelta
from functools import wraps
from tabulate import tabulate
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, List
from packages.logger.logger import P_Log, DEFAULT_LOGGER_NAME
from config import config


# Get configuration singleton instance
cfg = config()

# Initialize logger early
logger = P_Log(log_to_console=False, split_by_level=True)

# Common regex patterns
EMAIL_PATTERN = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$")
DOMAIN_PATTERN = re.compile(r'@([^@]+)$')
WHITESPACE_PATTERN = re.compile(r'\s+')
SPF_PATTERN = re.compile(r'\bv=spf1\b')
DKIM_PATTERN = re.compile(r'\bv=DKIM1\b')
BANNER_CLEANUP_PATTERN = re.compile(r'[\r\n\t]+')

# DNS record patterns
DMARC_PATTERN = re.compile(r'v=DMARC1')
SPF_STRICT_PATTERN = re.compile(r'v=spf1.*?(?:-all|~all)')

# Error classification patterns
TIMEOUT_PATTERN = re.compile(r'timeout|timed?\s*out', re.IGNORECASE)
REFUSED_PATTERN = re.compile(r'refused|reject|denied|block', re.IGNORECASE)
NOT_FOUND_PATTERN = re.compile(r'not\s+found|no\s+such|doesn\'t\s+exist|invalid', re.IGNORECASE)
BLACKLIST_PATTERN = re.compile(r'blacklist|spam|block', re.IGNORECASE)

# Define these variables before using them
smtp_pool = None

# Global variables initialization
_last_execution_time = 0.0
_next_nameserver_index = 0

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

# DNS Functions and Utilities
def rate_limiter(operation_name=None):
    """Rate limiter using sliding window with per-nameserver tracking."""
    def decorator(func):
        # Use dictionary to track requests by nameserver
        requests_by_server = {}
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            nonlocal requests_by_server
            
            # Get the nameserver parameters from kwargs
            nameserver = kwargs.get('_rate_limit_key', 'default')
            nameserver_list = kwargs.get('_nameserver_list', None)
            nameserver_index = kwargs.get('_nameserver_index', 0)
            
            # Initialize tracking deque for this nameserver if it doesn't exist
            if nameserver not in requests_by_server:
                requests_by_server[nameserver] = deque()
            
            requests = requests_by_server[nameserver]
            
            # Get rate limit settings from database
            rate_limit_config = None
            try:
                if operation_name and hasattr(cfg.rate_limit, operation_name):
                    rate_limit_config = getattr(cfg.rate_limit, operation_name)
            except Exception as e:
                logger.warning(f"Failed to get rate limit config for {operation_name}: {e}")
            
            # Get rate limit settings with default fallback values
            try:
                max_requests = cfg.rate_limit.max_requests
                if max_requests is None:
                    max_requests = 10  # Default to 10 requests if not configured
                    logger.warning(f"No max_requests configured for {operation_name}, using default: 10")
            except Exception:
                max_requests = 10  # Default fallback
                logger.warning(f"Error retrieving max_requests for {operation_name}, using default: 10")
            
            try:
                time_window = cfg.rate_limit.time_window
                if time_window is None:
                    time_window = 1.0  # Default to 1 second if not configured
                    logger.warning(f"No time_window configured for {operation_name}, using default: 1.0")
            except Exception:
                time_window = 1.0  # Default fallback
                logger.warning(f"Error retrieving time_window for {operation_name}, using default: 1.0")
            
            if rate_limit_config:
                try:
                    config_max_requests = rate_limit_config.get('max_requests')
                    if config_max_requests is not None:
                        max_requests = config_max_requests
                        
                    config_time_window = rate_limit_config.get('time_window')
                    if config_time_window is not None:
                        time_window = config_time_window
                except Exception as e:
                    logger.warning(f"Error parsing operation-specific rate limit config: {e}")
            
            now = time.time()
            
            while requests and now - requests[0] > time_window:
                requests.popleft()
                
            # Check if we've hit the limit (now safe with fallback values)
            if len(requests) >= max_requests:
                wait_time = requests[0] + time_window - now
                if wait_time > 0:
                    # Use a more descriptive nameserver ID in logs
                    ns_id = nameserver if nameserver != 'default' else 'primary DNS'
                    logger.warning(f"Rate limit reached for nameserver {ns_id}. Waiting {wait_time:.2f} seconds...")
                    
                    # If nameserver_list wasn't passed, try to get it from cfg
                    if not nameserver_list:
                        try:
                            dns_servers = cfg.dns_setting.nameservers
                            if isinstance(dns_servers, str):
                                nameserver_list = [s.strip() for s in dns_servers.split(',')]
                            else:
                                nameserver_list = list(dns_servers) if dns_servers else []
                            logger.debug(f"Loaded nameserver list from config: {nameserver_list}")
                        except Exception as e:
                            logger.warning(f"Could not load nameservers from config: {e}")
                    
                    # Try switching to next nameserver if available
                    if nameserver_list and nameserver_index < len(nameserver_list) - 1:
                        next_index = nameserver_index + 1
                        next_server = nameserver_list[next_index]
                        logger.info(f"Rate limit reached for {nameserver}, switching to {next_server}")
                        
                        # Create new kwargs with the next nameserver
                        new_kwargs = kwargs.copy()
                        new_kwargs['_nameserver_index'] = next_index
                        new_kwargs['_rate_limit_key'] = next_server
                        new_kwargs['_nameserver_list'] = nameserver_list  # Make sure to pass the list
                        
                        # Call function with updated nameserver
                        return func(*args, **new_kwargs)
                    else:
                        logger.debug(f"No alternate nameservers available. nameserver_list={nameserver_list}, index={nameserver_index}")
                    
                    # If no alternate nameserver, wait
                    time.sleep(wait_time)
            
            # Add this request to the tracking queue
            result = func(*args, **kwargs)
            requests.append(time.time())
            return result
        return wrapper
    return decorator

@rate_limiter(operation_name='dns_lookup')
@ttl_cache('mx_record')
def get_mx_record(domain: str, _nameserver_list=None, _nameserver_index=0, _rate_limit_key=None) -> Optional[List[dns.resolver.Answer]]:
    """Cached MX record lookup with per-nameserver rate limiting"""
    try:
        # Use explicit nameservers if configured
        resolver = dns.resolver.Resolver()
        
        # Get nameservers from config if not explicitly provided
        if (_nameserver_list is None):
            nameservers = cfg.dns_setting.nameservers
            if isinstance(nameservers, str):
                _nameserver_list = list(nameservers) if nameservers else []
        
        # If we have nameservers but no rate limit key, set it to the current nameserver
        if _nameserver_list and _nameserver_index < len(_nameserver_list):
            current_server = _nameserver_list[_nameserver_index]
            
            # Set rate limit key if not provided
            if (_rate_limit_key is None):
                _rate_limit_key = current_server
                
            # Configure resolver to use just the current nameserver
            resolver.nameservers = [current_server]
            logger.debug(f"Attempting DNS lookup for {domain} using nameserver: {current_server}")
        
        # Get timeout from config
        lifetime = cfg.dns_setting.timeout
        
        # Perform the lookup
        answers = resolver.resolve(domain, 'MX', lifetime=lifetime)
        if answers:
            # Log which nameserver actually handled the request
            logger.info(f"DNS query for {domain} successfully handled by nameserver: {_rate_limit_key}")
            return sorted(answers, key=lambda x: x.preference)
        
        logger.warning(f"No MX records found for {domain}")
        return None
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers) as e:
        logger.debug(f"DNS lookup failed for {domain}: {e}")
    except dns.exception.DNSException as e:
        logger.debug(f"DNS operation failed for {domain}: {e}")
    except Exception as e:
        logger.warning(f"Unexpected error in DNS operation for {domain}: {e}")
    return None

@ttl_cache('ttl_cache')
@rate_limiter(operation_name='dns_lookup')
def check_spf(domain, _nameserver_list=None, _nameserver_index=0, _rate_limit_key=None):
    """Check for SPF record in domain's TXT records."""
    try:
        # Use explicit nameservers if configured
        resolver = dns.resolver.Resolver()
        
        # Get nameservers from config if not explicitly provided
        if _nameserver_list is None:
            nameservers = cfg.dns_setting.nameservers
            if isinstance(nameservers, str):
                _nameserver_list = [s.strip() for s in nameservers.split(',')]
            else:
                _nameserver_list = list(nameservers) if nameservers else []
        
        # If we have nameservers but no rate limit key, set it to the current nameserver
        if _nameserver_list and _nameserver_index < len(_nameserver_list):
            current_server = _nameserver_list[_nameserver_index]
            
            # Set rate limit key if not provided
            if _rate_limit_key is None:
                _rate_limit_key = current_server
                
            # Configure resolver to use just the current nameserver
            resolver.nameservers = [current_server]
                
        lifetime = cfg.dns_setting.timeout
        
        answers = resolver.resolve(domain, 'TXT', lifetime=lifetime)
        for rdata in answers:
            if SPF_PATTERN.search(str(rdata)):
                return "SPF Found"
        return "No SPF Record"
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers) as e:
        logger.debug(f"DNS lookup failed for {domain}: {e}")
    except dns.exception.DNSException as e:
        logger.debug(f"DNS operation failed for {domain}: {e}")
    except Exception as e:
        logger.warning(f"Unexpected error in DNS operation for {domain}: {e}")
    return "SPF Check Error"

@ttl_cache('ttl_cache')
@rate_limiter(operation_name='dns_lookup')
def check_dkim(domain, _nameserver_list=None, _nameserver_index=0, _rate_limit_key=None):
    """Check for DKIM TXT record in domain's DNS settings."""
    try:
        # Use explicit nameservers if configured
        resolver = dns.resolver.Resolver()
        
        # Get nameservers from config if not explicitly provided
        if _nameserver_list is None:
            nameservers = cfg.dns_setting.nameservers
            if isinstance(nameservers, str):
                _nameserver_list = [s.strip() for s in nameservers.split(',')]
            else:
                _nameserver_list = list(nameservers) if nameservers else []
        
        # If we have nameservers but no rate limit key, set it to the current nameserver
        if _nameserver_list and _nameserver_index < len(_nameserver_list):
            current_server = _nameserver_list[_nameserver_index]
            
            # Set rate limit key if not provided
            if _rate_limit_key is None:
                _rate_limit_key = current_server
                
            # Configure resolver to use just the current nameserver
            resolver.nameservers = [current_server]
                
        lifetime = cfg.dns_setting.timeout
        
        # Get DKIM selector from config
        dkim_selector = cfg.dns_setting.dkim_selector
        dkim_domain = f"{dkim_selector}._domainkey.{domain}"
        
        answers = resolver.resolve(dkim_domain, 'TXT', lifetime=lifetime)
        for rdata in answers:
            if DKIM_PATTERN.search(str(rdata)):
                return "DKIM Found"
        return "No DKIM Record"
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers) as e:
        logger.debug(f"DNS lookup failed for {domain}: {e}")
    except dns.exception.DNSException as e:
        logger.debug(f"DNS operation failed for {domain}: {e}")
    except Exception as e:
        logger.warning(f"Unexpected error in DNS operation for {domain}: {e}")
    return "DKIM Check Error"

@rate_limiter(operation_name='dns_lookup')
def get_mx_ip(server, _nameserver_list=None, _nameserver_index=0, _rate_limit_key=None):
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
def test_smtp_connection(server, port, email, **kwargs):
    """Test SMTP connection to a server using database configuration"""
    # Get settings from database via config
    retries = cfg.smtp_setting.max_retries
    timeout = cfg.smtp_setting.timeout
    retry_delay = cfg.smtp_setting.retry_delay
    test_sender = cfg.smtp_setting.test_sender
    
    # Extract domain from server for domain-specific tracking
    domain_parts = server.split('.')
    base_domain = '.'.join(domain_parts[-2:]) if len(domain_parts) >= 2 else server
    
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
            error_str = str(e)
            logger.debug(f"SMTP connection error on attempt {attempt + 1} for {server}:{port} - {e}")
            
            # Check for rejection patterns
            if "450" in error_str or "refused" in error_str.lower() or "reject" in error_str.lower():
                # Add this domain to a temporary blocklist 
                with cfg.connect() as conn:
                    cursor = conn.cursor()
                    # Update or insert blocked domain with extended cooldown
                    cooldown_minutes = 30 * (attempt + 1)  # Increase cooldown with each attempt
                    cursor.execute(
                        "INSERT OR REPLACE INTO temp_blocked_domains (domain, blocked_until) VALUES (?, ?)",
                        (base_domain, (datetime.now() + timedelta(minutes=cooldown_minutes)).isoformat())
                    )
                    conn.commit()
                logger.warning(f"Server {server} has rejected our connection. Cooling down for {cooldown_minutes} minutes.")
                break  # Don't retry if we've been explicitly rejected
                
            if attempt + 1 < retries:
                # Use exponential backoff
                backoff_time = retry_delay * (2 ** attempt)
                logger.debug(f"Backing off for {backoff_time} seconds before retry")
                time.sleep(backoff_time)
                continue
    logger.debug(f"SMTP connection failed after {retries} attempts for {email} on {server}:{port}")
    return False

@rate_limiter(operation_name='smtp_vrfy')
def smtp_vrfy(server, port, email, _nameserver_list=None, _nameserver_index=0, _rate_limit_key=None):
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

@rate_limiter(operation_name='smtp_connection')
def get_smtp_banner(server, _nameserver_list=None, _nameserver_index=0, _rate_limit_key=None):
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
            return BANNER_CLEANUP_PATTERN.sub(' ', result).strip()
    except Exception as e:
        return str(e)

#  Check Functions (IMAP/POP3)
@rate_limiter(operation_name='imap_connection')
def check_imap_ssl(server, _nameserver_list=None, _nameserver_index=0, _rate_limit_key=None):
    """Check if the server supports IMAP over SSL on port 993."""
    try:
        imap = imaplib.IMAP4_SSL(server, 993, timeout=5)
        banner = imap.welcome.decode() if isinstance(imap.welcome, bytes) else imap.welcome
        imap.logout()
        return "Available", banner.replace("\n", " ").strip()
    except Exception as e:
        return "Not available", str(e)

@rate_limiter(operation_name='pop3_connection')
def check_pop3_ssl(server, _nameserver_list=None, _nameserver_index=0, _rate_limit_key=None):
    """Check if the server supports POP3 over SSL on port 995."""
    try:
        pop = poplib.POP3_SSL(server, 995, timeout=5)
        banner = pop.getwelcome().decode() if isinstance(pop.getwelcome(), bytes) else pop.getwelcome()
        pop.quit()
        return "Available", banner.replace("\n", " ").strip()
    except Exception as e:
        return "Not available", str(e)

@rate_limiter(operation_name='dns_lookup')
def check_server_policies(domain: str, _nameserver_list=None, _nameserver_index=0, _rate_limit_key=None) -> str:
    """Check if the domain has any specific anti-verification policies"""
    policies = []
    
    # Check for DMARC policy
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        for rdata in answers:
            if "v=DMARC1" in str(rdata):
                policies.append("DMARC")
                break
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers) as e:
        logger.debug(f"DNS lookup failed for {domain}: {e}")
    except dns.exception.DNSException as e:
        logger.debug(f"DNS operation failed for {domain}: {e}")
    except Exception as e:
        logger.warning(f"Unexpected error in DNS operation for {domain}: {e}")
    
    # Check for RFC 7208 (SPF) reject policies
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt = str(rdata)
            if "v=spf1" in txt and ("-all" in txt or "~all"):
                policies.append("Strict SPF")
                break
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers) as e:
        logger.debug(f"DNS lookup failed for {domain}: {e}")
    except dns.exception.DNSException as e:
        logger.debug(f"DNS operation failed for {domain}: {e}")
    except Exception as e:
        logger.warning(f"Unexpected error in DNS operation for {domain}: {e}")
    
    # Check for explicit reject policies in TXT records
    if policies:
        return ", ".join(policies)
    else:
        return "None detected"

def is_domain_blocked(domain):
    """Check if domain is temporarily blocked due to previous rejections"""
    try:
        with cfg.connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT blocked_until FROM temp_blocked_domains WHERE domain = ?", 
                (domain,)
            )
            result = cursor.fetchone()
            
            if result:
                blocked_until = datetime.fromisoformat(result['blocked_until'])
                if blocked_until > datetime.now():
                    # Still in cooldown period
                    minutes_left = (blocked_until - datetime.now()).total_seconds() / 60
                    logger.debug(f"Domain {domain} is blocked for {minutes_left:.1f} more minutes")
                    return True
                else:
                    # Cooldown period expired, remove from blocklist
                    cursor.execute("DELETE FROM temp_blocked_domains WHERE domain = ?", (domain,))
                    conn.commit()
            
            return False
    except Exception as e:
        logger.error(f"Error checking domain blocklist: {e}")
        return False

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
        'execution_time': kwargs.get('execution_time', 0.0),
        'batch_id': kwargs.get('batch_id', None)  # Add support for batch_id
    }
    
    # Remove extra whitespace from string values
    for key, value in data.items():
        if isinstance(value, str):
            data[key] = WHITESPACE_PATTERN.sub(' ', value).strip()
    
    try:
        with cfg.connect() as conn:
            cursor = conn.cursor()
            
            # Check if this email already exists in the database
            # Only check for duplicates when NOT part of a batch
            if data['batch_id'] is None:
                cursor.execute("SELECT id, check_count FROM email_validation_records WHERE email = ? ORDER BY timestamp DESC LIMIT 1", (email,))
                existing_record = cursor.fetchone()
            else:
                # For batch processing, always create a new record
                existing_record = None
            
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
                # First time checking this email or part of a batch, insert a new record
                # Add batch_id to the query
                cursor.execute("""
                    INSERT INTO email_validation_records (
                        timestamp, email, domain, smtp_result, mx_record, port, disposable, spf_status, dkim_status,
                        catch_all, blacklist_info, mx_preferences, smtp_banner, mx_ip,
                        error_message, imap_status, imap_info, pop3_status, pop3_info, server_policies,
                        confidence_score, execution_time, check_count, batch_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
                """, (
                    data['timestamp'], data['email'], data['domain'], data['smtp_result'], data['mx_record'], data['port'],
                    data['disposable'], data['spf_status'], data['dkim_status'], data['catch_all'], 
                    data['blacklist_info'], data['mx_preferences'], data['smtp_banner'], data['mx_ip'],
                    data['error_message'], data['imap_status'], data['imap_banner'], data['pop3_status'], 
                    data['pop3_banner'], data['server_policies'], data['confidence_score'], data['execution_time'],
                    data['batch_id']
                ))
                logger.debug(f"Created new record for {email}" + (f" in batch {data['batch_id']}" if data['batch_id'] else ""))
            
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
    # Extract batch_id from kwargs for passing to log_email_check
    batch_id = kwargs.get('batch_id')
    
    global _next_nameserver_index
    logger.info(f"Starting validation for email: {email}")
    confidence_score = 0

    # Add this near the start of validate_email()
    domain = email.split('@')[1].lower()
    if is_domain_blocked(domain):
        logger.info(f"Domain {domain} is currently blocked due to previous rejections")
        return f"Domain temporarily unavailable (Confidence: Low, 0/100)"

    try:
        # Check email format
        email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$"
        if not EMAIL_PATTERN.match(email):
            # Calculate execution time even for early returns
            execution_time = time.time() - _start_time if _start_time else 0.0
            
            log_email_check(email, "Invalid Format", "N/A", "N/A", "Invalid Email Format",
                          "N/A", "N/A", error_message="Invalid email format", 
                          blacklist_info=check_blacklists(email),
                          confidence_score=0,
                          execution_time=execution_time,
                          batch_id=batch_id)  # Explicitly pass batch_id
            return "Invalid email format."
        else:
            confidence_score += cfg.validation_scoring.valid_format
            
        domain_match = DOMAIN_PATTERN.search(email)
        domain = domain_match.group(1) if domain_match else ""
        disposable_status = "Disposable" if is_disposable_email(email) else "Not Disposable"
        
        # Penalize disposable emails
        if disposable_status == "Not Disposable":
            confidence_score += cfg.validation_scoring.not_disposable
        else:
            confidence_score += cfg.validation_scoring.disposable
            
        logger.debug(f"Email {'is' if disposable_status == 'Disposable' else 'is not'} disposable, " 
                     f"{'subtracting 10 from' if disposable_status == 'Disposable' else 'adding 10 to'} "
                     f"confidence score (now {confidence_score})")
        
        blacklist_info = check_blacklists(email)
        
        # Penalize blacklisted domains
        if blacklist_info != "Not Blacklisted":
            confidence_score += cfg.validation_scoring.blacklisted
        
        smtp_vrfy_result = ""
        catch_all_email = ""
        mx_preferences = ""
        smtp_banner = ""
        mx_ip = ""
        
        # Replace print statements with logger.debug calls
        logger.debug(f"Checking MX records for {domain}")
        
        # Get nameservers from config for initial request
        nameservers = cfg.dns_setting.nameservers
        if isinstance(nameservers, str):
            nameserver_list = [s.strip() for s in nameservers.split(',')]
        else:
            nameserver_list = list(nameservers) if nameservers else []
            
        # Use the rotation index to choose which nameserver to start with
        if nameserver_list:
            # Use modulo to cycle through available nameservers
            current_index = _next_nameserver_index % len(nameserver_list)
            # Increment for next call
            _next_nameserver_index += 1
            
            mx_records = get_mx_record(domain, 
                                      _nameserver_list=nameserver_list, 
                                      _nameserver_index=current_index, 
                                      _rate_limit_key=nameserver_list[current_index])
        else:
            mx_records = get_mx_record(domain)
            
        if not mx_records:
            # Calculate execution time even for early returns
            execution_time = time.time() - _start_time if _start_time else 0.0

            # Set confidence score to 0 for domains with no MX records
            confidence_score = 0
            
            # Get confidence level label
            confidence_level = get_confidence_level(confidence_score)
            
            # Format result with confidence information
            result_with_confidence = f"No mail servers found (Confidence: {confidence_level}, {confidence_score}/100)"
            
            log_email_check(email, "No MX Records", "N/A", "N/A", "Could not verify email", "N/A", domain,
                          error_message="No MX records found", blacklist_info=blacklist_info, 
                          disposable_status=disposable_status, confidence_score=confidence_score,
                          execution_time=execution_time,
                          batch_id=batch_id)  # Explicitly pass batch_id
            return result_with_confidence
        else:
            confidence_score += cfg.validation_scoring.mx_records
            logger.debug(f"MX records found for {domain}, adding 20 to confidence score (now {confidence_score})")
        
        primary_mx = str(mx_records[0].exchange).rstrip('.')
        logger.debug(f"Primary MX for {domain} is {primary_mx}")
        
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
            if test_smtp_connection(primary_mx, port, email):
                smtp_result = "Email likely exists"
                used_port = port
                logger.info(f"Connection successful on port {port} for {email}")
                confidence_score += cfg.validation_scoring.smtp_connection
                break
                
        if smtp_result == "Email likely exists":
            fake_email = f"nonexistent{int(time.time())}@{domain}"
            if test_smtp_connection(primary_mx, used_port, fake_email):
                smtp_result = "Email likely exists"
                catch_all_email = fake_email
                logger.info(f"Catch-all detected for {domain} using {fake_email}")
                # Use logger instead of print for catch-all detection
                logger.debug(f"Catch-all detected: {fake_email} (email likely exists)")
                confidence_score += cfg.validation_scoring.catch_all
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
        if (_start_time is not None):
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
            execution_time=execution_time,
            batch_id=batch_id  # Explicitly pass batch_id
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
                      execution_time=execution_time,
                      batch_id=batch_id)  # Explicitly pass batch_id
        raise

@performance_monitor
def validate_emails(emails, batch_id=None, _start_time=None):
    """
    Validate multiple email addresses in parallel and return results
    
    Args:
        emails (list): List of email addresses to validate
        batch_id (int, optional): Batch ID for database tracking
        _start_time (float, optional): Start time passed by performance_monitor decorator
        
    Returns:
        list: Validation results for each email
    """
    # Get thread pool max workers from config
    try:
        max_workers = cfg.thread_pool_setting.max_worker_threads
    except:
        max_workers = min(32, (os.cpu_count() or 1) * 2)  # Default fallback
        
    logger.debug(f"Validating {len(emails)} emails with {max_workers} workers" + 
                 (f" for batch {batch_id}" if batch_id else ""))
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all validation tasks to the thread pool
        futures = []
        for email in emails:
            # Pass batch_id to validate_email function
            futures.append(executor.submit(validate_email, email, batch_id=batch_id))
            
        # Collect results as they complete
        results = []
        for future in as_completed(futures):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                logger.error(f"Error during email validation: {e}")
                results.append(f"Error: {str(e)}")
    
    return results

# --- Show log---   

def load_batch_column_settings():
    """Load column display settings for batch info from config"""
    logger.debug("Loading column display settings for batch view")
    
    try:
        # Get visible columns with proper ordering from batch_info_field_definitions
        with cfg.connect() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT name, display_name 
                FROM batch_info_field_definitions 
                WHERE visible = 1
                ORDER BY display_index ASC
            """)
            display_settings = cursor.fetchall()
            
            if not display_settings:
                logger.warning("No batch column display settings found in database")
                return []
                
            return display_settings
    except Exception as e:
        logger.error(f"Error loading batch column settings: {e}")
        return []  # Return empty list on error to allow fallback display

def display_logs_custom_gui(date_range=None, domain_filter=None, confidence_levels=None, email_search=None):
    """GUI-friendly version of display_logs_custom that takes filter parameters as arguments
    
    Args:
        date_range (tuple, optional): Tuple containing (start_date, end_date) as datetime objects
        domain_filter (str, optional): Domain to filter by
        confidence_levels (list, optional): List of confidence level strings to include
        email_search (str, optional): Text to search for in email addresses
        
    Returns:
        dict: Results dictionary containing:
            - headers: List of column headers
            - rows: List of rows with data
            - filter_summary: Text describing applied filters
            - record_count: Number of records returned
            - total_count: Total number of matching records
    """
    try:
        results = {
            'headers': [],
            'rows': [],
            'filter_summary': "No filters applied",
            'record_count': 0,
            'total_count': 0
        }
        
        # Get list of actual columns from the table
        logger.debug("Loading column display settings for custom log view")
        
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
                logger.warning("No column display settings found in database.")
                return results
        
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
            logger.warning("No matching columns found between definitions and the actual table.")
            return results
            
        # First, check if there are any records at all
        with cfg.connect() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) AS count FROM email_validation_records")
            total_records = cursor.fetchone()['count']
            
        if total_records == 0:
            logger.info("No email validation records found in the database.")
            return results
            
        # Build WHERE clause and query parameters from provided filter parameters
        where_clauses = []
        query_params = []
        
        # 1. Process date range filter
        if date_range:
            start_date, end_date = date_range
            
            if start_date:
                where_clauses.append("timestamp >= ?")
                query_params.append(start_date.isoformat())
            if end_date:
                where_clauses.append("timestamp <= ?")
                query_params.append(end_date.isoformat())
        
        # 2. Process domain filter
        if domain_filter:
            # Split by commas and handle each domain
            domains = [d.strip() for d in domain_filter.split(',') if d.strip()]
            if domains:
                domain_conditions = []
                for domain in domains:
                    domain_conditions.append("domain LIKE ?")
                    query_params.append(f"%{domain}%")
                
                if domain_conditions:
                    where_clauses.append(f"({' OR '.join(domain_conditions)})")
        
        # 3. Process confidence level filter
        if confidence_levels:
            confidence_conditions = []
            for level in confidence_levels:
                if "Very Low" in level:
                    confidence_conditions.append("(confidence_score BETWEEN 0 AND 20)")
                elif "Low" in level and "Very" not in level:
                    confidence_conditions.append("(confidence_score BETWEEN 21 AND 40)")
                elif "Medium" in level:
                    confidence_conditions.append("(confidence_score BETWEEN 41 AND 60)")
                elif "High" in level and "Very" not in level:
                    confidence_conditions.append("(confidence_score BETWEEN 61 AND 80)")
                elif "Very High" in level:
                    confidence_conditions.append("(confidence_score BETWEEN 81 AND 100)")
            
            if confidence_conditions:
                where_clauses.append(f"({' OR '.join(confidence_conditions)})")
                
        # 4. Process email search
        if email_search:
            # Split by commas and handle each search term
            search_terms = [t.strip() for t in email_search.split(',') if t.strip()]
            if search_terms:
                email_conditions = []
                for term in search_terms:
                    email_conditions.append("email LIKE ?")
                    query_params.append(f"%{term}%")
                
                if email_conditions:
                    where_clauses.append(f"({' OR '.join(email_conditions)})")
            
        # Build the WHERE clause
        where_clause = ""
        if where_clauses:
            where_clause = "WHERE " + " AND ".join(where_clauses)
        
        # Fetch logs from database with limit from app settings
        display_limit = cfg.app_setting.get('general', 'log_display_limit')
        logger.debug(f"Fetching up to {display_limit} logs from database with custom filters")
        
        # Build the query dynamically based on the actual columns and filters
        with cfg.connect() as conn:
            cursor = conn.cursor()
            query = f"SELECT {', '.join(actual_columns)} FROM email_validation_records {where_clause} ORDER BY timestamp DESC LIMIT ?"
            query_params.append(display_limit)
            cursor.execute(query, tuple(query_params))
            records = cursor.fetchall()
            
            # Get count of total matching records (without limit)
            count_query = f"SELECT COUNT(*) as count FROM email_validation_records {where_clause}"
            cursor.execute(count_query, tuple(query_params[:-1]))  # Exclude the LIMIT parameter
            filtered_count = cursor.fetchone()['count']
        
        if not records:
            logger.info("No email validation records found matching the filters.")
            return results
        
        # Prepare headers and rows for results
        headers = [column_map.get(col, col.capitalize()) for col in actual_columns]
        rows = []
        
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
                    
                row.append(value)
            rows.append(row)
        
        # Build filter summary for display
        filter_summary = []
        if date_range:
            start_date, end_date = date_range
            date_range_parts = []
            if start_date:
                date_range_parts.append(f"from {start_date.strftime('%Y-%m-%d')}")
            if end_date:
                date_range_parts.append(f"to {end_date.strftime('%Y-%m-%d')}")
            if date_range_parts:
                filter_summary.append("Date: " + " ".join(date_range_parts))
        
        if domain_filter:
            filter_summary.append(f"Domain: {domain_filter}")
            
        if confidence_levels:
            filter_summary.append(f"Confidence: {', '.join(confidence_levels)}")
            
        if email_search:
            filter_summary.append(f"Email text: {email_search}")
            
        filter_display = "No filters applied"
        if filter_summary:
            filter_display = " | ".join(filter_summary)
        
        # Populate results
        results['headers'] = headers
        results['rows'] = rows
        results['filter_summary'] = filter_display
        results['record_count'] = len(records)
        results['total_count'] = filtered_count
        
        return results
        
    except Exception as e:
        log_exception("Error displaying custom logs from GUI", e)
        return {
            'headers': [],
            'rows': [],
            'filter_summary': f"Error: {str(e)}",
            'record_count': 0,
            'total_count': 0
        }

def display_logs_custom():
    """Display email verification logs with custom filtering options
    
    Allows filtering by:
    - Date Range
    - Domain
    - Confidence Status
    - Custom Text Search (local part of email)
    - Also shows domains in cooldown with time remaining
    """
    try:
        # Get list of actual columns from the table
        logger.debug("Loading column display settings for custom log view")
        
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
            total_records = cursor.fetchone()['count']
            
        if total_records == 0:
            print("\nNo email validation logs found in the database.")
            logger.info("No email validation records found in the database.")
            return
            
        # ------ FILTERING OPTIONS ------
        print("\n=== Custom Log Filter Options ===")
        
        # 1. Date Range Filter
        date_filter_active = False
        start_date = None
        end_date = None
        date_filter = input("\nFilter by date range? (y/n): ").strip().lower()
        if date_filter == 'y':
            date_filter_active = True
            print("Enter start date (format: YYYY-MM-DD, leave empty for no start limit): ")
            start_date_input = input().strip()
            if start_date_input:
                try:
                    start_date = datetime.fromisoformat(start_date_input)
                    start_date = start_date.replace(hour=0, minute=0, second=0)  # Start of day
                except ValueError:
                    print("Invalid date format. Using no start date limit.")
                    start_date = None
            
            print("Enter end date (format: YYYY-MM-DD, leave empty for no end limit): ")
            end_date_input = input().strip()
            if end_date_input:
                try:
                    end_date = datetime.fromisoformat(end_date_input)
                    end_date = end_date.replace(hour=23, minute=59, second=59)  # End of day
                except ValueError:
                    print("Invalid date format. Using no end date limit.")
                    end_date = None
        
        # 2. Domain Filter
        domain_filter = ""
        domain_filter_input = input("\nFilter by domain (leave empty for all domains): ").strip().lower()
        if domain_filter_input:
            domain_filter = domain_filter_input
        
        # 3. Status/Confidence Level Filter
        confidence_filter_active = False
        confidence_levels = []
        
        # First, get available confidence levels and their counts
        with cfg.connect() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT 
                    CASE 
                        WHEN confidence_score BETWEEN 0 AND 20 THEN 'Very Low (0-20)'
                        WHEN confidence_score BETWEEN 21 AND 40 THEN 'Low (21-40)'
                        WHEN confidence_score BETWEEN 41 AND 60 THEN 'Medium (41-60)'
                        WHEN confidence_score BETWEEN 61 AND 80 THEN 'High (61-80)'
                        WHEN confidence_score BETWEEN 81 AND 100 THEN 'Very High (81-100)'
                        ELSE 'Unknown'
                    END as confidence_level,
                    COUNT(*) as count
                FROM email_validation_records
                GROUP BY confidence_level
                ORDER BY MIN(confidence_score)
            """)
            confidence_counts = cursor.fetchall()
        
        if confidence_counts:
            print("\nAvailable confidence levels:")
            for i, level in enumerate(confidence_counts, 1):
                print(f"{i}. {level['confidence_level']} ({level['count']} emails)")
            
            confidence_filter = input("\nFilter by confidence level? (y/n): ").strip().lower()
            if confidence_filter == 'y':
                confidence_filter_active = True
                print("Enter level numbers to include (comma-separated, e.g. 1,3,5): ")
                level_input = input().strip()
                
                if level_input:
                    try:
                        selected_indices = [int(idx.strip()) for idx in level_input.split(',')]
                        for idx in selected_indices:
                            if 1 <= idx <= len(confidence_counts):
                                level_name = confidence_counts[idx-1]['confidence_level']
                                confidence_levels.append(level_name)
                        
                        if confidence_levels:
                            print(f"Selected confidence levels: {', '.join(confidence_levels)}")
                        else:
                            confidence_filter_active = False
                            print("No valid confidence levels selected. Showing all levels.")
                    except ValueError:
                        confidence_filter_active = False
                        print("Invalid input. Showing all confidence levels.")
        
        # 4. Custom Text Search (local part of email - before @)
        email_search = ""
        email_search_input = input("\nSearch for specific text in email address (leave empty for all): ").strip()
        if email_search_input:
            email_search = email_search_input
            
        # Build the WHERE clause based on filters
        where_clauses = []
        query_params = []
        
        if date_filter_active:
            if start_date:
                where_clauses.append("timestamp >= ?")
                query_params.append(start_date.isoformat())
            if end_date:
                where_clauses.append("timestamp <= ?")
                query_params.append(end_date.isoformat())
                
        if domain_filter:
            where_clauses.append("domain LIKE ?")
            query_params.append(f"%{domain_filter}%")
            
        if confidence_filter_active and confidence_levels:
            confidence_conditions = []
            for level in confidence_levels:
                if "Very Low" in level:
                    confidence_conditions.append("(confidence_score BETWEEN 0 AND 20)")
                elif "Low" in level and "Very" not in level:
                    confidence_conditions.append("(confidence_score BETWEEN 21 AND 40)")
                elif "Medium" in level:
                    confidence_conditions.append("(confidence_score BETWEEN 41 AND 60)")
                elif "High" in level and "Very" not in level:
                    confidence_conditions.append("(confidence_score BETWEEN 61 AND 80)")
                elif "Very High" in level:
                    confidence_conditions.append("(confidence_score BETWEEN 81 AND 100)")
            
            if confidence_conditions:
                where_clauses.append(f"({' OR '.join(confidence_conditions)})")
                
        if email_search:
            where_clauses.append("email LIKE ?")
            query_params.append(f"%{email_search}%")
            
        # Combine all filters into final WHERE clause
        where_clause = ""
        if where_clauses:
            where_clause = "WHERE " + " AND ".join(where_clauses)
        
        # Fetch logs from database with limit from app settings
        display_limit = cfg.app_setting.get('general', 'log_display_limit')
        logger.debug(f"Fetching up to {display_limit} logs from database with custom filters")
        
        # Build the query dynamically based on the actual columns and filters
        with cfg.connect() as conn:
            cursor = conn.cursor()
            query = f"SELECT {', '.join(actual_columns)} FROM email_validation_records {where_clause} ORDER BY timestamp DESC LIMIT ?"
            query_params.append(display_limit)
            cursor.execute(query, tuple(query_params))
            records = cursor.fetchall()
            
            # Get count of total matching records (without limit)
            count_query = f"SELECT COUNT(*) as count FROM email_validation_records {where_clause}"
            cursor.execute(count_query, tuple(query_params[:-1]))  # Exclude the LIMIT parameter
            filtered_count = cursor.fetchone()['count']
        
        if not records:
            print("\nNo email validation records found matching your filters.")
            return
        
        # Show domains in cooldown
        print("\n=== Domains in Cooldown ===")
        with cfg.connect() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT domain, blocked_until 
                FROM temp_blocked_domains 
                WHERE blocked_until > ?
                ORDER BY blocked_until DESC
            """, (datetime.now().isoformat(),))
            blocked_domains = cursor.fetchall()
            
        if blocked_domains:
            cooldown_table = []
            for domain in blocked_domains:
                blocked_until = datetime.fromisoformat(domain['blocked_until'])
                time_left = blocked_until - datetime.now()
                minutes_left = time_left.total_seconds() / 60
                cooldown_table.append([
                    domain['domain'],
                    f"{minutes_left:.1f} minutes" if minutes_left < 60 else f"{minutes_left/60:.1f} hours"
                ])
            
            print(tabulate(
                cooldown_table,
                headers=["Domain", "Time Left"],
                tablefmt='grid',
                numalign='left',
                stralign='left'
            ))
        else:
            print("No domains are currently in cooldown.")
            
        # Prepare headers and rows for tabulation
        headers = [column_map.get(col, col.capitalize()) for col in actual_columns]
        rows = []
        
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
        
        # Display filter summary
        filter_summary = []
        if date_filter_active:
            date_range = []
            if start_date:
                date_range.append(f"from {start_date.strftime('%Y-%m-%d')}")
            if end_date:
                date_range.append(f"to {end_date.strftime('%Y-%m-%d')}")
            if date_range:
                filter_summary.append("Date: " + " ".join(date_range))
        
        if domain_filter:
            filter_summary.append(f"Domain: {domain_filter}")
            
        if confidence_filter_active and confidence_levels:
            filter_summary.append(f"Confidence: {', '.join(confidence_levels)}")
            
        if email_search:
            filter_summary.append(f"Email text: {email_search}")
            
        filter_display = "No filters applied"
        if filter_summary:
            filter_display = " | ".join(filter_summary)
        
        # Display formatted data
        print(f"\nFiltered Email Validation Logs: {filter_display}")
        print(tabulate(
            rows,
            headers=headers,
            tablefmt='grid',
            numalign='left',
            stralign='left'
        ))
        print(f"\nShowing {len(records)} of {filtered_count} filtered records (limited to {display_limit}).")
        
    except Exception as e:
        log_exception("Error displaying custom logs", e)

def display_logs_all():
    """Display all email verification logs from email_validation_records (including batch records)"""
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
            total_records = cursor.fetchone()['count']
            
        if total_records == 0:
            print("\nNo email validation logs found in the database.")
            logger.info("No email validation records found in the database.")
            return
        
        # Fetch logs from database with limit from app settings
        display_limit = cfg.app_setting.get('general', 'log_display_limit')
        logger.debug(f"Fetching up to {display_limit} logs from database (all records)")
        
        # Build the query dynamically based on the actual columns - no WHERE clause to fetch all records
        with cfg.connect() as conn:
            cursor = conn.cursor()
            query = f"SELECT {', '.join(actual_columns)} FROM email_validation_records ORDER BY timestamp DESC LIMIT ?"
            cursor.execute(query, (display_limit,))
            records = cursor.fetchall()
        
        if not records:
            print("\nNo email validation records found.")
            return
        
        # Prepare headers and rows for tabulation
        headers = [column_map.get(col, col.capitalize()) for col in actual_columns]
        rows = []
        
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
        print("\nAll Email Validation Logs:")
        print(tabulate(
            rows,
            headers=headers,
            tablefmt='grid',
            numalign='left',
            stralign='left'
        ))
        print(f"\nShowing {len(records)} of {total_records} records (limited to {display_limit}).")
        
    except Exception as e:
        log_exception("Error displaying logs", e)

def display_logs(batch_id):
    """Display email verification logs for a specific batch ID.
    
    Args:
        batch_id (int): The batch ID to display logs for
    """
    try:
        # First, check if the batch exists
        with cfg.connect() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM batch_info WHERE id = ?", (batch_id,))
            batch_record = cursor.fetchone()
            
            if not batch_record:
                print(f"\nBatch ID {batch_id} not found in database.")
                logger.warning(f"Attempted to view non-existent batch ID: {batch_id}")
                return
                
            # Convert to a regular dictionary immediately
            batch_info = dict(batch_record)
            
        # Get list of columns to display
        logger.debug("Loading column display settings")
        
        # Get visible columns with proper ordering from email_records_field_definitions
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
        
        # Check if there are any records for this batch
        with cfg.connect() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) AS count FROM email_validation_records WHERE batch_id = ?", (batch_id,))
            record_count = cursor.fetchone()['count']
            
            if record_count == 0:
                print(f"\nNo email validation records found for batch ID {batch_id}.")
                return
        
        # Fetch logs from database for this batch
        logger.debug(f"Fetching logs for batch ID {batch_id}")
        
        with cfg.connect() as conn:
            cursor = conn.cursor()
            query = f"SELECT {', '.join(actual_columns)} FROM email_validation_records WHERE batch_id = ? ORDER BY timestamp ASC"
            cursor.execute(query, (batch_id,))
            records = cursor.fetchall()
        
        # Prepare headers and rows for tabulation
        headers = [column_map.get(col, col.capitalize()) for col in actual_columns]
        rows = []
        
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
        
        # Display email records for this batch
        print(f"\nEmail Validation Records for Batch ID {batch_id} ({batch_info['name']}):")
        print(tabulate(
            rows,
            headers=headers,
            tablefmt='grid',
            numalign='left',
            stralign='left'
        ))
        
        # Display batch information at the bottom with simple formatting
        print("\n\n=== Batch Information ===\n")
        
        # Debug: Log what we retrieved from the database
        logger.debug(f"Batch info: {batch_info}")
        
        # Get batch column settings
        display_settings = load_batch_column_settings()
        logger.debug(f"Loaded {len(display_settings)} batch column display settings")
        
        # If we have batch display settings
        if display_settings:
            try:
                for setting in display_settings:
                    col_name = setting['name']
                    display_name = setting['display_name']
                    
                    if col_name in batch_info:
                        value = batch_info[col_name]
                        
                        # Format datetime values nicely
                        if col_name in ['created_at', 'completed_at', 'updated_at'] and value:
                            try:
                                dt = datetime.fromisoformat(value)
                                value = dt.strftime("%Y-%m-%d %H:%M:%S")
                            except Exception as e:
                                logger.debug(f"Error formatting date for {col_name}: {e}")
                                # Don't fail completely, use the original value
                                pass
                        
                        # Print property and value (ensure value is a string)
                        print(f"{display_name}: {value}")
                    else:
                        # Log missing fields for debugging
                        logger.debug(f"Field '{col_name}' not found in batch_info")
                
                # Calculate success rate if applicable
                if 'total_emails' in batch_info and batch_info['total_emails'] > 0 and 'success_count' in batch_info:
                    success_rate = (batch_info['success_count'] / batch_info['total_emails']) * 100
                    print(f"Success Rate: {success_rate:.1f}%")
            except Exception as e:
                # Log any errors and fall back to the basic display
                logger.error(f"Error displaying batch info using settings: {e}")
                # If the custom display fails, fall back to basic display
                print("Error using display settings, showing basic information instead:")
                _display_basic_batch_info(batch_info)
        else:
            # Fallback if no display settings
            _display_basic_batch_info(batch_info)
        
        # Calculate processing time if we have created_at and completed_at
        if 'created_at' in batch_info and 'completed_at' in batch_info and batch_info['completed_at']:
            try:
                start_time = datetime.fromisoformat(batch_info['created_at'])
                end_time = datetime.fromisoformat(batch_info['completed_at'])
                processing_time = (end_time - start_time).total_seconds()
                
                # Format processing time
                if processing_time < 60:
                    time_str = f"{processing_time:.2f} seconds"
                elif processing_time < 3600:
                    time_str = f"{processing_time/60:.2f} minutes"
                else:
                    time_str = f"{processing_time/3600:.2f} hours"
                    
                print(f"Processing Time: {time_str}")
            except Exception as e:
                logger.warning(f"Error calculating processing time: {e}")
        
    except Exception as e:
        log_exception("Error displaying batch logs", e)

# Add a helper function to display basic batch information
def _display_basic_batch_info(batch_info):
    """Helper function to display basic batch information"""
    if not batch_info:
        print("No batch information available")
        return
        
    for key, value in batch_info.items():
        # Skip internal fields like id
        if key == 'id':
            continue
        
        # Format datetime values
        if key in ['created_at', 'completed_at', 'updated_at'] and value:
            try:
                dt = datetime.fromisoformat(value)
                value = dt.strftime("%Y-%m-%d %H:%M:%S")
            except:
                pass
        
        # Print property and value (ensure value is converted to string)
        print(f"{key.replace('_', ' ').title()}: {value}")

def display_logs_standalone():
    """Display standalone email verification logs from email_validation_records (where batch_id is NULL)"""
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
        
        # First, check if there are any standalone records at all
        with cfg.connect() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) AS count FROM email_validation_records WHERE batch_id IS NULL")
            total_records = cursor.fetchone()['count']
            
        if total_records == 0:
            print("\nNo standalone email validation logs found in the database.")
            logger.info("No standalone email validation records found in the database.")
            return
        
        # Fetch logs from database with limit from app settings
        display_limit = cfg.app_setting.get('general', 'log_display_limit')
        logger.debug(f"Fetching up to {display_limit} standalone logs from database")
        
        # Build the query dynamically based on the actual columns - only for standalone records
        with cfg.connect() as conn:
            cursor = conn.cursor()
            query = f"SELECT {', '.join(actual_columns)} FROM email_validation_records WHERE batch_id IS NULL ORDER BY timestamp ASC LIMIT ?"
            cursor.execute(query, (display_limit,))
            records = cursor.fetchall()
        
        if not records:
            print("\nNo standalone email validation records found.")
            return
        
        # Prepare headers and rows for tabulation
        headers = [column_map.get(col, col.capitalize()) for col in actual_columns]
        rows = []
        
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
        print("\nStandalone Email Validation Logs:")
        print(tabulate(
            rows,
            headers=headers,
            tablefmt='grid',
            numalign='left',
            stralign='left'
        ))
        print(f"\nShowing {len(records)} of {total_records} standalone records (limited to {display_limit}).")
        
    except Exception as e:
        log_exception("Error displaying logs", e)

def clear_log_all():
    """Clear ALL email logs from the table including batch records and batch information
    
    Returns:
        dict: Dictionary containing operation results:
            - success (bool): Whether operation was successful
            - message (str): Human-readable result message
            - count (int): Number of records deleted (0 if table was empty)
            - status (str): Status code describing the result
    """
    result = {
        'success': False,
        'message': '',
        'count': 0,
        'status': 'error'
    }
    
    try:
        logger.debug("Starting complete log clearing process")
        
        # First check if the tables are empty
        conn = cfg.connect()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) AS record_count FROM email_validation_records")
        email_records_count = cursor.fetchone()['record_count']
        
        cursor.execute("SELECT COUNT(*) AS batch_count FROM batch_info")
        batch_info_count = cursor.fetchone()['batch_count']
        
        if email_records_count == 0 and batch_info_count == 0:
            logger.info("No records found - nothing to clear")
            result['success'] = True
            result['message'] = "No records to delete"
            result['status'] = 'empty'
            conn.close()
            return result
        
        # Execute the deletion - delete ALL records from both tables
        logger.debug(f"Clearing all {email_records_count} records from email_validation_records and {batch_info_count} records from batch_info")
        
        # Delete from email_validation_records first
        cursor.execute("DELETE FROM email_validation_records") 
        email_affected_rows = conn.total_changes
        
        # Then delete from batch_info
        cursor.execute("DELETE FROM batch_info")
        batch_affected_rows = conn.total_changes - email_affected_rows
        
        conn.commit()
        
        # Store the number of affected rows
        total_affected_rows = email_affected_rows + batch_affected_rows
        logger.info(f"All logs have been cleared successfully. Removed {email_affected_rows} email records and {batch_affected_rows} batch records.")
        
        result['success'] = True
        result['message'] = f"Successfully cleared all {email_affected_rows} email records and {batch_affected_rows} batch records"
        result['count'] = total_affected_rows
        result['status'] = 'cleared'
        conn.close()
        
    except Exception as e:
        error_msg = f"Error clearing logs: {str(e)}"
        log_exception("Error clearing logs", e)
        result['message'] = error_msg
        result['status'] = 'error'
        
    logger.debug(f"Log clearing process complete with status: {result['status']}")
    return result

def lines_in_batch(batch_id):
    """Get the number of email records in a specific batch
    
    Args:
        batch_id (int): The batch ID to check
        
    Returns:
        int: Number of records with the specified batch ID
    """
    try:
        conn = cfg.connect()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) AS count FROM email_validation_records WHERE batch_id = ?", (batch_id,))
        count = cursor.fetchone()['count']
        conn.close()
        logger.info(f"Found {count} records in batch {batch_id}")
        return count
    except Exception as e:
        logger.error(f"Error getting batch record count: {str(e)}")
        return 0

def list_batches():
    """Get a list of all batches in the database
    
    Returns:
        list: List of dictionaries containing batch information
    """
    try:
        conn = cfg.connect()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT b.id, b.name as batch_name, b.created_at, b.total_emails,
               COUNT(e.id) as processed_emails
            FROM batch_info b
            LEFT JOIN email_validation_records e ON b.id = e.batch_id
            GROUP BY b.id, b.name, b.created_at, b.total_emails
            ORDER BY b.created_at DESC
        """)
        batches = cursor.fetchall()
        conn.close()
        
        # Convert to list of dictionaries
        result = [dict(batch) for batch in batches]
        logger.info(f"Retrieved {len(result)} batches from database")
        return result
    except Exception as e:
        logger.error(f"Error listing batches: {str(e)}")
        return []

def clear_batch(batch_id):
    """Clear all records for a specific batch ID
    
    Args:
        batch_id (int): The batch ID to clear
        
    Returns:
        dict: Dictionary containing operation results:
            - success (bool): Whether operation was successful
            - message (str): Human-readable result message
            - count (int): Number of records deleted (0 if batch was empty)
            - status (str): Status code describing the result
    """
    result = {
        'success': False,
        'message': '',
        'count': 0,
        'status': 'error'
    }
    
    try:
        logger.debug(f"Starting batch clearing process for batch ID: {batch_id}")
        
        # First check if the batch exists
        conn = cfg.connect()
        cursor = conn.cursor()
        
        # Check if batch exists in batch_info - using correct column name "name" instead of "batch_name"
        cursor.execute("SELECT name FROM batch_info WHERE id = ?", (batch_id,))
        batch = cursor.fetchone()
        
        if not batch:
            logger.info(f"Batch ID {batch_id} not found in database")
            result['message'] = f"Batch ID {batch_id} not found"
            result['status'] = 'not_found'
            conn.close()
            return result
        
        batch_name = batch['name']  # Use the correct column name
        
        # Count records for this batch
        cursor.execute("SELECT COUNT(*) AS count FROM email_validation_records WHERE batch_id = ?", (batch_id,))
        count = cursor.fetchone()['count']
        
        if count == 0:
            logger.info(f"No records found for batch ID {batch_id} - nothing to clear")
            
            # Delete the batch info record
            cursor.execute("DELETE FROM batch_info WHERE id = ?", (batch_id,))
            conn.commit()
            
            result['success'] = True
            result['message'] = f"Batch '{batch_name}' had no records. Batch info deleted."
            result['status'] = 'empty'
            conn.close()
            return result
        
        # Execute the deletion
        logger.debug(f"Clearing {count} records from batch ID {batch_id} ({batch_name})")
        
        # Delete email records for this batch
        cursor.execute("DELETE FROM email_validation_records WHERE batch_id = ?", (batch_id,))
        email_affected_rows = conn.total_changes
        
        # Delete the batch info record
        cursor.execute("DELETE FROM batch_info WHERE id = ?", (batch_id,))
        batch_affected = 1 if conn.total_changes > email_affected_rows else 0
        
        conn.commit()
        
        # Store the number of affected rows
        total_affected_rows = email_affected_rows + batch_affected
        logger.info(f"Batch {batch_id} ({batch_name}) has been cleared successfully. Removed {email_affected_rows} email records and batch info.")
        
        result['success'] = True
        result['message'] = f"Successfully cleared batch '{batch_name}' with {email_affected_rows} email records"
        result['count'] = total_affected_rows
        result['status'] = 'cleared'
        conn.close()
        
    except Exception as e:
        error_msg = f"Error clearing batch: {str(e)}"
        log_exception("Error clearing batch", e)
        result['message'] = error_msg
        result['status'] = 'error'
        
    logger.debug(f"Batch clearing process complete with status: {result['status']}")
    return result

def clear_log_standalone():
    """Clear the email logs table and reset sequence counter
    
    Returns:
        dict: Dictionary containing operation results:
            - success (bool): Whether operation was successful
            - message (str): Human-readable result message
            - count (int): Number of records deleted (0 if table was empty)
            - status (str): Status code describing the result
    """
    result = {
        'success': False,
        'message': '',
        'count': 0,
        'status': 'error'
    }
    
    try:
        logger.debug("Starting log clearing process")
        
        # First check if the table is empty
        conn = cfg.connect()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) AS record_count FROM email_validation_records WHERE batch_id IS NULL")
        count = cursor.fetchone()['record_count']
        
        if count == 0:
            logger.info("No non-batch records found - nothing to clear")
            result['success'] = True
            result['message'] = "No standalone records to delete"
            result['status'] = 'empty'
            conn.close()
            return result
        
        # Execute the deletion - only for records where batch_id is NULL
        logger.debug(f"Clearing {count} non-batch records from email_validation_records table")
        cursor.execute("DELETE FROM email_validation_records WHERE batch_id IS NULL") 
        conn.commit()
        
        # Store the number of affected rows
        affected_rows = conn.total_changes
        logger.info(f"Non-batch logs have been cleared successfully. Removed {affected_rows} records.")
        
        result['success'] = True
        result['message'] = f"Successfully cleared {affected_rows} standalone records"
        result['count'] = affected_rows
        result['status'] = 'cleared'
        conn.close()
        
    except Exception as e:
        error_msg = f"Error clearing logs: {str(e)}"
        log_exception("Error clearing logs", e)
        result['message'] = error_msg
        result['status'] = 'error'
        
    logger.debug(f"Log clearing process complete with status: {result['status']}")
    return result

def record_count():
    """Get the number of records in the email_validation_records table
    
    Returns:
        int: Number of records in the table
    """
    try:
        conn = cfg.connect()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) AS count FROM email_validation_records")
        count = cursor.fetchone()['count']
        conn.close()
        logger.info(f"Record count retrieved successfully: {count}")
        return count
    except Exception as e:
        logger.error(f"Error getting record count: {str(e)}")
        return 0

def non_batch_record_count():
    """Get the number of non-batch records in the email_validation_records table
    
    Returns:
        int: Number of records in the table where batch_id IS NULL
    """
    try:
        conn = cfg.connect()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) AS count FROM email_validation_records WHERE batch_id IS NULL")
        count = cursor.fetchone()['count']
        conn.close()
        logger.info(f"Non-batch record count retrieved successfully: {count}")
        return count
    except Exception as e:
        logger.error(f"Error getting non-batch record count: {str(e)}")
        return 0

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

def get_user_info():
    """Return information about the current user"""
    try:
        user_info = cfg.get_active_user()
        print(
        "\n""- He yells this out in frustration,\n"
        "  and confusion as he tries to uncover his identity.\n"
        "\n"
        "USER INFORMATION: \n"
        )
        print(f"Name       : {user_info['name']}")
        print(f"E-mail     : {user_info['email']}")
        print(f"Created at : {user_info['created_at']}")
    except Exception as e:
        log_exception("Error retrieving user information", e)
        print(f"Error retrieving user information: {e}")

def refresh_db_state():
    """Refreshes the database state and clears cache"""
    try:
        # Check if database exists first
        db_dir = os.path.join(os.getcwd(), 'DB')
        db_path = os.path.join(db_dir, 'EVS.db')
        
        if not os.path.exists(db_path):
            error_msg = "Database file not found."
            logger.error(error_msg)
            return False
        
        # Only attempt to refresh if database exists
        try:
            cfg.refresh_db_state()
            logger.debug("Database connection refreshed and cache cleared")
            return True
        except Exception as e:
            error_msg = f"Error refreshing database state: {e}"
            logger.error(error_msg)
            return False
            
    except Exception as e:
        # Catch any other errors during path checking
        error_msg = f"Error checking database: {e}"
        logger.error(error_msg)
        print(f"Error: {error_msg}")
        return False

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
            except Exception as e:
                logger.debug(f"Error during SMTP cleanup: {e}")

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

def shutdown():
    """Properly shut down all Core module resources"""
    global smtp_pool, cfg
    
    try:
        logger.info("Core module shutting down...")
        
        # Track success and failures
        success_count = 0
        failed_operations = []
        
        # 1. First, refresh config caches to prevent later reloading
        try:
            # Reset any LRU caches in the config module
            if hasattr(cfg, 'refresh'):
                logger.debug("Refreshing config caches")
                cfg.refresh()
                logger.info("Step 1/9: Config caches refreshed successfully")
            else:
                logger.info("Step 1/9: No config caches to refresh")
            success_count += 1
        except Exception as e:
            logger.error(f"Step 1/9: Failed to refresh config caches: {e}")
            failed_operations.append("Config Caches")
        
        # 2. Close SMTP connection pool
        try:
            if smtp_pool:
                logger.debug("Closing SMTP connection pool")
                for server_key in list(smtp_pool.pool.keys()):
                    for smtp in smtp_pool.pool[server_key]:
                        try:
                            smtp.quit()
                        except Exception as e:
                            logger.debug(f"Error closing SMTP connection: {e}")
                smtp_pool.pool.clear()
                logger.info("Step 2/9: SMTP connection pool closed successfully")
                success_count += 1
            else:
                logger.info("Step 2/9: SMTP connection pool was not initialized, skipping")
                success_count += 1
        except Exception as e:
            logger.error(f"Step 2/9: Failed to close SMTP connection pool: {e}")
            failed_operations.append("SMTP Connection Pool")
        
        # 3. Clear cached data from ttl_cache decorators
        try:
            cache_cleared = False
            for name, func in globals().items():
                if callable(func) and hasattr(func, 'cache'):
                    logger.debug(f"Clearing cache for {name}")
                    func.cache.clear()
                    if hasattr(func, 'timestamps'):
                        func.timestamps.clear()
                    cache_cleared = True
            
            if cache_cleared:
                logger.info("Step 3/9: Function caches cleared successfully")
            else:
                logger.info("Step 3/9: No function caches to clear")
            success_count += 1
        except Exception as e:
            logger.error(f"Step 3/9: Failed to clear function caches: {e}")
            failed_operations.append("Cache Clearing")
        
        # 4. Close any active thread pools
        try:
            if 'thread_pool' in globals() and globals()['thread_pool']:
                logger.debug("Shutting down thread pool")
                globals()['thread_pool'].shutdown(wait=True)
                logger.info("Step 4/9: Thread pool shut down successfully")
            else:
                logger.info("Step 4/9: No active thread pools to shut down")
            success_count += 1
        except Exception as e:
            logger.error(f"Step 4/9: Failed to shut down thread pool: {e}")
            failed_operations.append("Thread Pool")
            
        # 5. Clear any pending background tasks - before DNS cleanup
        try:
            task_count = 0
            if 'background_tasks' in globals() and globals()['background_tasks']:
                logger.debug("Cancelling any pending background tasks")
                for task in globals()['background_tasks']:
                    if hasattr(task, 'cancel') and callable(task.cancel):
                        task.cancel()
                        task_count += 1
                        
            if task_count > 0:
                logger.info(f"Step 5/9: {task_count} background tasks cancelled successfully")
            else:
                logger.info("Step 5/9: No background tasks to cancel")
            success_count += 1
        except Exception as e:
            logger.error(f"Step 5/9: Failed to cancel background tasks: {e}")
            failed_operations.append("Background Tasks")
        
        # 6. Release any file locks - before DNS cleanup
        try:
            import glob
            lock_files = glob.glob(os.path.join(os.getcwd(), '*.lock'))
            if lock_files:
                for lock_file in lock_files:
                    try:
                        os.remove(lock_file)
                        logger.debug(f"Removed lock file: {lock_file}")
                    except Exception as e:
                        logger.warning(f"Could not remove lock file {lock_file}: {e}")
                logger.info(f"Step 6/9: Removed {len(lock_files)} lock files successfully")
            else:
                logger.info("Step 6/9: No lock files to remove")
            success_count += 1
        except Exception as e:
            logger.error(f"Step 6/9: Failed to clean up lock files: {e}")
            failed_operations.append("File Locks")
        
        # 7. Disconnect from database (do this BEFORE DNS operations)
        try:
            # Assuming cfg.connect() returns a connection that might need closing
            if hasattr(cfg, 'db') and cfg.db:
                logger.debug("Closing database connection")
                cfg.db.close()
                logger.info("Step 7/9: Database connection closed successfully")
            else:
                logger.info("Step 7/9: No direct database connection to close")
                
            # Close any persistent connection at class level
            if hasattr(cfg, '_connection') and cfg._connection:
                logger.debug("Closing persistent database connection")
                cfg._connection.close()
                cfg._connection = None
                
            success_count += 1
        except Exception as e:
            logger.error(f"Step 7/9: Failed to close database connection: {e}")
            failed_operations.append("Database Connection")
        
        # 8. NOW release DNS resolver resources - after DB is closed
        try:
            import dns.resolver
            if hasattr(dns.resolver, 'default_resolver') and dns.resolver.default_resolver:
                if hasattr(dns.resolver.default_resolver, 'reset'):
                    dns.resolver.default_resolver.reset()
                    logger.info("Step 8/9: DNS resolver reset successfully")
                elif hasattr(dns.resolver.default_resolver, 'nameservers'):
                    # Alternative approach: clear nameservers
                    dns.resolver.default_resolver.nameservers = []
                    logger.info("Step 8/9: DNS resolver nameservers cleared successfully")
                else:
                    logger.info("Step 8/9: DNS resolver has no reset method or nameservers attribute")
            else:
                logger.info("Step 8/9: No DNS resolver to reset")
            success_count += 1
        except Exception as e:
            logger.error(f"Step 8/9: Failed to reset DNS resolver: {e}")
            failed_operations.append("DNS Resolver")
        
        # 9. Final database state refresh
        try:
            if cfg and hasattr(cfg, 'refresh_db_state'):
                logger.debug("Final database state refresh")
                cfg.refresh_db_state()
                logger.info("Step 9/9: Final database state refresh completed")
            else:
                logger.info("Step 9/9: No database state to refresh")
            success_count += 1
        except Exception as e:
            logger.error(f"Step 9/9: Failed final database refresh: {e}")
            failed_operations.append("Final Database Refresh")
        
        # Log summary of shutdown process
        if failed_operations:
            logger.warning(f"Core module shutdown completed with {success_count}/9 successful operations. Failed operations: {', '.join(failed_operations)}")
        else:
            logger.info(f"Core module shutdown completed successfully ({success_count}/9 operations)")
            
        return True
        
    except Exception as e:
        logger.error(f"Critical error during Core shutdown: {e}", exc_info=True)
        return False

def start_batch_validation(batch_id):
    """Start batch validation process"""
    logger.info(f"Starting batch validation with ID: {batch_id}")
    # Batch validation logic here

def process_complete(batch_id, processed, success_count):
    """Process completion logic"""
    logger.info(f"Completing batch with ID: {batch_id}, processed: {processed}, success: {success_count}")
    # Completion logic here

def update_batch_status(batch_id):
    """Update batch status in database"""
    logger.info(f"Updated batch status in database, batch_id: {batch_id}")

    # export functions
    
def export_data(data, headers, format_type='csv', file_name=None):
        """
        Export data to CSV or JSON format
        
        Args:
            data: List of rows (each row is a list of values)
            headers: List of column headers
            format_type: 'csv' or 'json'
            file_name: Optional custom file name (without extension)
            
        Returns:
            dict: Export result with keys:
                - success (bool): Whether export was successful
                - file_path (str): Path to the exported file
                - count (int): Number of records exported
                - format (str): Format of the exported file ('csv' or 'json')
                - message (str): Result message
        """
        result = {
            'success': False,
            'file_path': '',
            'count': len(data),
            'format': format_type.lower(),
            'message': ''
        }
        
        try:
            # Create exports directory if it doesn't exist
            export_dir = os.path.join(os.getcwd(), 'exports')
            if not os.path.exists(export_dir):
                os.makedirs(export_dir)
                
            # Generate timestamp for filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Create filename
            if file_name:
                safe_name = ''.join(c if c.isalnum() or c in ['-', '_'] else '_' for c in file_name)
                base_name = f"{safe_name}_{timestamp}"
            else:
                base_name = f"export_{timestamp}"
                
            # Export based on format
            if format_type.lower() == 'csv':
                file_path = os.path.join(export_dir, f"{base_name}.csv")
                
                with open(file_path, 'w', newline='', encoding='utf-8') as csv_file:
                    csv_writer = csv.writer(csv_file)
                    csv_writer.writerow(headers)
                    csv_writer.writerows(data)
                    
                result['file_path'] = file_path
                result['success'] = True
                result['message'] = f"Successfully exported {len(data)} records to CSV"
                
            elif format_type.lower() == 'json':
                file_path = os.path.join(export_dir, f"{base_name}.json")
                
                # Convert data to list of dictionaries
                json_data = []
                for row in data:
                    json_data.append(dict(zip(headers, row)))
                    
                with open(file_path, 'w', encoding='utf-8') as json_file:
                    json.dump(json_data, json_file, indent=2, ensure_ascii=False)
                    
                result['file_path'] = file_path
                result['success'] = True
                result['message'] = f"Successfully exported {len(data)} records to JSON"
            
            else:
                result['message'] = f"Unsupported format: {format_type}"
                
            logger.info(f"Exported {len(data)} records to {format_type} file: {result['file_path']}")
            return result
            
        except Exception as e:
            error_message = f"Export error: {str(e)}"
            logger.error(error_message, exc_info=True)
            result['message'] = error_message
            return result

def export_date_range(start_date=None, end_date=None, format_type='csv'):
                """
                Export email validation records within a date range
                
                Args:
                    start_date (datetime): Start date for filtering
                    end_date (datetime): End date for filtering
                    format_type (str): 'csv' or 'json'
                    
                Returns:
                    dict: Export result
                """
                try:
                    where_clauses = []
                    query_params = []
                    
                    if start_date:
                        where_clauses.append("timestamp >= ?")
                        query_params.append(start_date.isoformat())
                        
                    if end_date:
                        where_clauses.append("timestamp <= ?")
                        query_params.append(end_date.isoformat())
                        
                    where_clause = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""
                    
                    with cfg.connect() as conn:
                        cursor = conn.cursor()
                        
                        # First, get all column names from the table
                        cursor.execute("PRAGMA table_info(email_validation_records)")
                        columns = [row['name'] for row in cursor.fetchall()]
                        
                        # Execute the query with date range filtering
                        query = f"SELECT * FROM email_validation_records {where_clause} ORDER BY timestamp DESC"
                        cursor.execute(query, tuple(query_params))
                        records = cursor.fetchall()
                        
                        if not records:
                            return {
                                'success': False, 
                                'message': "No records found in the specified date range",
                                'count': 0,
                                'format': format_type,
                                'file_path': ''
                            }
                        
                        # Prepare data for export
                        headers = columns
                        data = []
                        
                        for record in records:
                            row = []
                            for col in columns:
                                row.append(record[col])
                            data.append(row)
                        
                        # Generate appropriate filename with date range info
                        date_str = ""
                        if start_date and end_date:
                            date_str = f"from_{start_date.strftime('%Y%m%d')}_to_{end_date.strftime('%Y%m%d')}"
                        elif start_date:
                            date_str = f"from_{start_date.strftime('%Y%m%d')}"
                        elif end_date:
                            date_str = f"to_{end_date.strftime('%Y%m%d')}"
                            
                        file_name = f"date_range_{date_str}" if date_str else "all_dates"
                        
                        # Export the data
                        return export_data(data, headers, format_type, file_name)
                
                except Exception as e:
                    error_message = f"Date range export error: {str(e)}"
                    logger.error(error_message, exc_info=True)
                    return {
                        'success': False,
                        'message': error_message,
                        'count': 0,
                        'format': format_type,
                        'file_path': ''
                    }
                
def export_batch(batch_id, format_type='csv'):
                    """
                    Export email validation records for a specific batch
                    
                    Args:
                        batch_id (int): Batch ID to export
                        format_type (str): 'csv' or 'json'
                        
                    Returns:
                        dict: Export result
                    """
                    try:
                        # First check if the batch exists
                        with cfg.connect() as conn:
                            cursor = conn.cursor()
                            cursor.execute("SELECT name FROM batch_info WHERE id = ?", (batch_id,))
                            batch = cursor.fetchone()
                            
                            if not batch:
                                return {
                                    'success': False,
                                    'message': f"Batch ID {batch_id} not found",
                                    'count': 0,
                                    'format': format_type,
                                    'file_path': ''
                                }
                                
                            batch_name = batch['name']
                            
                            # Get all column names from the table
                            cursor.execute("PRAGMA table_info(email_validation_records)")
                            columns = [row['name'] for row in cursor.fetchall()]
                            
                            # Get records for this batch
                            cursor.execute(
                                f"SELECT * FROM email_validation_records WHERE batch_id = ? ORDER BY timestamp ASC",
                                (batch_id,)
                            )
                            records = cursor.fetchall()
                            
                            if not records:
                                return {
                                    'success': False,
                                    'message': f"No records found for batch ID {batch_id}",
                                    'count': 0,
                                    'format': format_type,
                                    'file_path': ''
                                }
                            
                            # Prepare data for export
                            headers = columns
                            data = []
                            
                            for record in records:
                                row = []
                                for col in columns:
                                    row.append(record[col])
                                data.append(row)
                                
                            # Generate filename with batch info
                            safe_batch_name = ''.join(c if c.isalnum() or c in ['-', '_'] else '_' for c in batch_name)
                            file_name = f"batch_{batch_id}_{safe_batch_name}"
                            
                            # Export the data
                            return export_data(data, headers, format_type, file_name)
                            
                    except Exception as e:
                        error_message = f"Batch export error: {str(e)}"
                        logger.error(error_message, exc_info=True)
                        return {
                            'success': False,
                            'message': error_message,
                            'count': 0,
                            'format': format_type,
                            'file_path': ''
                        }
def export_domain(domains, format_type='csv'):
    """
    Export email validation records for specific domains
    
    Args:
        domains (list or str): Domain or list of domains to export
        format_type (str): 'csv' or 'json'
        
    Returns:
        dict: Export result
    """
    try:
        # Handle single domain as string or multiple domains as list
        if isinstance(domains, str):
            domains = [domains.strip()]
        elif isinstance(domains, list):
            domains = [d.strip() for d in domains if d.strip()]
        
        if not domains:
            return {
                'success': False,
                'message': "No domains specified",
                'count': 0,
                'format': format_type,
                'file_path': ''
            }
        
        # Build query for multiple domains
        placeholders = ', '.join(['?'] * len(domains))
        
        with cfg.connect() as conn:
            cursor = conn.cursor()
            
            # Get all column names from the table
            cursor.execute("PRAGMA table_info(email_validation_records)")
            columns = [row['name'] for row in cursor.fetchall()]
            
            # Get records for these domains
            cursor.execute(
                f"SELECT * FROM email_validation_records WHERE domain IN ({placeholders}) ORDER BY domain, timestamp DESC",
                tuple(domains)
            )
            records = cursor.fetchall()
            
            if not records:
                return {
                    'success': False,
                    'message': f"No records found for the specified domain(s)",
                    'count': 0,
                    'format': format_type,
                    'file_path': ''
                }
            
            # Prepare data for export
            headers = columns
            data = []
            
            for record in records:
                row = []
                for col in columns:
                    row.append(record[col])
                data.append(row)
                
            # Generate filename with domain info
            if len(domains) == 1:
                domain_str = domains[0]
            else:
                domain_str = f"multiple_{len(domains)}"
                
            file_name = f"domain_{domain_str}"
            
            # Export the data
            return export_data(data, headers, format_type, file_name)
            
    except Exception as e:
        error_message = f"Domain export error: {str(e)}"
        logger.error(error_message, exc_info=True)
        return {
            'success': False,
            'message': error_message,
            'count': 0,
            'format': format_type,
            'file_path': ''
}

def export_confidence(confidence_levels, format_type='csv'):
    """
    Export email validation records with specific confidence levels
    
    Args:
        confidence_levels (list): List of confidence level names 
                                 (Very Low, Low, Medium, High, Very High)
        format_type (str): 'csv' or 'json'
        
    Returns:
        dict: Export result
    """
    try:
        if not confidence_levels or not isinstance(confidence_levels, list):
            return {
                'success': False,
                'message': "No confidence levels specified",
                'count': 0,
                'format': format_type,
                'file_path': ''
            }
        
        # Build confidence level conditions
        confidence_conditions = []
        for level in confidence_levels:
            if "Very Low" in level:
                confidence_conditions.append("(confidence_score BETWEEN 0 AND 20)")
            elif "Low" in level and "Very" not in level:
                confidence_conditions.append("(confidence_score BETWEEN 21 AND 40)")
            elif "Medium" in level:
                confidence_conditions.append("(confidence_score BETWEEN 41 AND 60)")
            elif "High" in level and "Very" not in level:
                confidence_conditions.append("(confidence_score BETWEEN 61 AND 80)")
            elif "Very High" in level:
                confidence_conditions.append("(confidence_score BETWEEN 81 AND 100)")
        
        if not confidence_conditions:
            return {
                'success': False,
                'message': "Invalid confidence levels specified",
                'count': 0,
                'format': format_type,
                'file_path': ''
            }
            
        # Build WHERE clause
        where_clause = "WHERE " + " OR ".join(confidence_conditions)
        
        with cfg.connect() as conn:
            cursor = conn.cursor()
            
            # Get all column names from the table
            cursor.execute("PRAGMA table_info(email_validation_records)")
            columns = [row['name'] for row in cursor.fetchall()]
            
            # Get records for these confidence levels
            query = f"SELECT * FROM email_validation_records {where_clause} ORDER BY confidence_score DESC, timestamp DESC"
            cursor.execute(query)
            records = cursor.fetchall()
            
            if not records:
                return {
                    'success': False,
                    'message': f"No records found for the specified confidence levels",
                    'count': 0,
                    'format': format_type,
                    'file_path': ''
                }
            
            # Prepare data for export
            headers = columns
            data = []
            
            for record in records:
                row = []
                for col in columns:
                    row.append(record[col])
                data.append(row)
                
            # Generate filename with confidence level info
            level_str = "_".join(level.lower().replace(" ", "_") for level in confidence_levels)
            file_name = f"confidence_{level_str}"
            
            # Export the data
            return export_data(data, headers, format_type, file_name)
            
    except Exception as e:
        error_message = f"Confidence level export error: {str(e)}"
        logger.error(error_message, exc_info=True)
        return {
            'success': False,
            'message': error_message,
            'count': 0,
            'format': format_type,
            'file_path': ''
        }

def export_all(format_type='csv'):
    """
    Export all email validation records with all fields
    
    Args:
        format_type (str): 'csv' or 'json'
        
    Returns:
        dict: Export result
    """
    try:
        with cfg.connect() as conn:
            cursor = conn.cursor()
            
            # Get all column names from the table
            cursor.execute("PRAGMA table_info(email_validation_records)")
            columns = [row['name'] for row in cursor.fetchall()]
            
            # Get all records
            cursor.execute("SELECT * FROM email_validation_records ORDER BY timestamp DESC")
            records = cursor.fetchall()
            
            if not records:
                return {
                    'success': False,
                    'message': "No records found in the database",
                    'count': 0,
                    'format': format_type,
                    'file_path': ''
                }
            
            # Prepare data for export
            headers = columns
            data = []
            
            for record in records:
                row = []
                for col in columns:
                    row.append(record[col])
                data.append(row)
                
            # Generate filename
            file_name = f"all_records"
            
            # Export the data
            return export_data(data, headers, format_type, file_name)
            
    except Exception as e:
        error_message = f"All records export error: {str(e)}"
        logger.error(error_message, exc_info=True)
        return {
            'success': False,
            'message': error_message,
            'count': 0,
            'format': format_type,
            'file_path': ''
        }

def export_meta(categories, format_type='csv'):
    """
    Export email validation records filtered by metadata categories
    
    Args:
        categories (list): List of categories to include 
                          ('Metadata', 'Core', 'Security', 'Technical', 'Protocol')
        format_type (str): 'csv' or 'json'
        
    Returns:
        dict: Export result
    """
    try:
        if not categories or not isinstance(categories, list):
            return {
                'success': False,
                'message': "No categories specified",
                'count': 0,
                'format': format_type,
                'file_path': ''
            }
        
        with cfg.connect() as conn:
            cursor = conn.cursor()
            
            # Get field definitions based on categories
            placeholders = ', '.join(['?'] * len(categories))
            cursor.execute(
                f"""
                SELECT name 
                FROM email_records_field_definitions 
                WHERE category IN ({placeholders})
                ORDER BY display_index
                """, 
                tuple(categories)
            )
            field_defs = cursor.fetchall()
            
            if not field_defs:
                return {
                    'success': False,
                    'message': f"No fields found for the specified categories",
                    'count': 0,
                    'format': format_type,
                    'file_path': ''
                }
            
            # Extract field names
            fields = [field['name'] for field in field_defs]
            
            # Always include email and timestamp for context
            if 'email' not in fields:
                fields.insert(0, 'email')
            if 'timestamp' not in fields:
                fields.insert(0, 'timestamp')
                
            # Get records with selected fields
            field_list = ', '.join(fields)
            cursor.execute(f"SELECT {field_list} FROM email_validation_records ORDER BY timestamp DESC")
            records = cursor.fetchall()
            
            if not records:
                return {
                    'success': False,
                    'message': "No records found in the database",
                    'count': 0,
                    'format': format_type,
                    'file_path': ''
                }
            
            # Prepare data for export
            headers = fields
            data = []
            
            for record in records:
                row = []
                for field in fields:
                    row.append(record[field])
                data.append(row)
                
            # Generate filename with category info
            category_str = "_".join(cat.lower() for cat in categories)
            file_name = f"meta_{category_str}"
            
            # Export the data
            return export_data(data, headers, format_type, file_name)
            
    except Exception as e:
        error_message = f"Metadata export error: {str(e)}"
        logger.error(error_message, exc_info=True)
        return {
            'success': False,
            'message': error_message,
            'count': 0,
            'format': format_type,
            'file_path': ''
        }

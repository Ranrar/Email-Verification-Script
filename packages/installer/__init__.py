import os
import sqlite3
import logging
from datetime import datetime
import json
from typing import Any, Dict
from packages.logger.logger import P_Log

# logging
logger = P_Log(logger_name='evs', log_to_console=False)

def clear_screen():
    """Clear the console screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

class Installer:
    # Class-level variables for singleton pattern
    _instance = None
    _initialized = False
    
    def __new__(cls, config=None):
        if cls._instance is None:
            cls._instance = super(Installer, cls).__new__(cls)
            cls._instance._initialized = False
            logger.debug("Creating new Installer singleton instance")
        return cls._instance

    def __init__(self, config=None):
        """Initialize database with optional config"""
        if self._initialized:
            return
            
        logger.info("Initializing installer")
        
        # Basic attributes
        self.db_dir = os.path.join(os.getcwd(), 'DB')
        self.db_path = os.path.join(self.db_dir, 'EVS.db')
        self.config = config
        self.current_user = None
        
        # Create DB directory if needed
        if not os.path.exists(self.db_dir):
            logger.info(f"Creating database directory: {self.db_dir}")
            os.makedirs(self.db_dir)
        
        # Set first run flag
        self.first_run = not os.path.exists(self.db_path)
        
        if self.first_run:
            logger.info("First run detected - initializing new database")
            self._initialize_new_database()
        else:
            logger.info(f"Using existing database at {self.db_path}")
        
        self._initialized = True
        
    # Rest of your class methods remain the same
    def _initialize_new_database(self):
        """Initialize a new database with user information"""
        print(""
"======================================================================\n"
    "Email Verification Script - Version 1.0\n"
    "Copyright (C) 2025 Kim Skov Rasmussen\n"
    "Licensed under GNU General Public License v3.0\n"  
    "This software is provided as is, without any warranties.\n"  
    "Use at your own risk. For educational purposes only.\n"
    "\n"
    "To get started, please create a user profile.\n"
"======================================================================\n"
"")

        print("\nPlease enter your user information:")
        while True:
            name = input("Name: ").strip()
            if name:
                break
            print("Name cannot be empty.")
        
        while True:
            email = input("Email: ").strip()
            if '@' in email and '.' in email:
                break
            print("Please enter a valid email address.")

        try:
            # Initialize database structure
            self.init_database()
            
            # Add initial user with no alias
            self.add_user(name, email)
            
            # Populate default settings
            self.populate_default_settings()
            
        except Exception as e:
            logger.error(f"Error creating database: {str(e)}")
            # Clean up if anything fails
            if os.path.exists(self.db_path):
                os.remove(self.db_path)
            
    def init_database(self):
        """Initialize the database"""
        try:
            logger.info("database tabels")
            
            # If the file is being accessed by another process, it might help to add a retry mechanism
            max_attempts = 3
            attempt = 0
            
            while attempt < max_attempts:
                try:
                    with sqlite3.connect(self.db_path) as conn:
                        # All your CREATE TABLE statements
                        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                created_at TEXT NOT NULL,
                is_active INTEGER DEFAULT 0
            )
        """)
                        conn.execute("""
            CREATE TABLE IF NOT EXISTS app_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                category TEXT NOT NULL,
                name TEXT NOT NULL,
                value TEXT NOT NULL,
                data_type TEXT NOT NULL,
                description TEXT,
                UNIQUE(category, name)
            )
        """)
                        conn.execute("""
                CREATE TABLE IF NOT EXISTS validation_scoring (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    check_name TEXT NOT NULL UNIQUE,
                    score_value INTEGER NOT NULL,
                    is_penalty INTEGER NOT NULL DEFAULT 0,
                    description TEXT
                )
                """)
                        conn.execute("""
            CREATE TABLE IF NOT EXISTS confidence_levels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                level_name TEXT NOT NULL UNIQUE,
                min_threshold INTEGER NOT NULL,
                max_threshold INTEGER NOT NULL,
                description TEXT
            )
        """)
                        conn.execute("""
            CREATE TABLE IF NOT EXISTS smtp_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                setting_name TEXT NOT NULL UNIQUE,
                value TEXT NOT NULL,
                data_type TEXT NOT NULL,
                description TEXT
            )
        """)
                        conn.execute("""
            CREATE TABLE IF NOT EXISTS smtp_ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                port INTEGER NOT NULL,
                priority INTEGER NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                UNIQUE(port)
            )
        """)
                        conn.execute("""
            CREATE TABLE IF NOT EXISTS imap_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                setting_name TEXT NOT NULL UNIQUE,
                value TEXT NOT NULL,
                data_type TEXT NOT NULL,
                description TEXT
            )
        """)
                        conn.execute("""
            CREATE TABLE IF NOT EXISTS pop3_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                setting_name TEXT NOT NULL UNIQUE,
                value TEXT NOT NULL,
                data_type TEXT NOT NULL,
                description TEXT
            )
        """)
                        conn.execute("""
            CREATE TABLE IF NOT EXISTS rate_limits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                operation TEXT NOT NULL UNIQUE,
                max_requests INTEGER NOT NULL,
                time_window INTEGER NOT NULL,
                description TEXT
            )
        """)
                        conn.execute("""
            CREATE TABLE IF NOT EXISTS cache_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cache_name TEXT NOT NULL UNIQUE,
                max_size INTEGER NOT NULL,
                ttl_seconds INTEGER NOT NULL,
                cleanup_interval INTEGER NOT NULL,
                description TEXT
            )
        """)
                        conn.execute("""
            CREATE TABLE IF NOT EXISTS thread_pool_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                setting_name TEXT NOT NULL UNIQUE,
                value INTEGER NOT NULL,
                description TEXT
            )
        """)
                        conn.execute("""
            CREATE TABLE IF NOT EXISTS dns_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                setting_name TEXT NOT NULL UNIQUE,
                value TEXT NOT NULL,
                data_type TEXT NOT NULL,
                description TEXT
            )
        """)
                        conn.execute("""
            CREATE TABLE IF NOT EXISTS blacklisted_domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                source TEXT NOT NULL,
                added_date TEXT NOT NULL,
                UNIQUE(domain, source)
            )
        """)
                        conn.execute("""
            CREATE TABLE IF NOT EXISTS disposable_domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL UNIQUE,
                added_date TEXT NOT NULL
            )
        """)
                        conn.execute("""
            CREATE TABLE IF NOT EXISTS email_validation_records (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        email TEXT NOT NULL,
                        domain TEXT NOT NULL,
                        smtp_result TEXT NOT NULL,
                        error_message TEXT,
                        disposable TEXT,
                        spf_status TEXT,
                        dkim_status TEXT,
                        blacklist_info TEXT,
                        mx_record TEXT,
                        port TEXT,
                        mx_ip TEXT,
                        mx_preferences TEXT,
                        smtp_banner TEXT,
                        smtp_vrfy TEXT,
                        catch_all TEXT,
                        imap_status TEXT,
                        imap_info TEXT,
                        pop3_status TEXT,
                        pop3_info TEXT,
                        server_policies TEXT,
                        check_count INTEGER DEFAULT 1,
                        confidence_score INTEGER DEFAULT 0,
                        execution_time REAL DEFAULT 0
            )
        """)
                        conn.execute("""
            CREATE TABLE IF NOT EXISTS email_records_field_definitions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                category TEXT NOT NULL,
                display_index INTEGER NOT NULL,
                visible INTEGER NOT NULL DEFAULT 1,
                description TEXT
            )
        """)
                        # Commit at the end
                        conn.commit()
                        logger.info("Database tabels created successfully")
                        return True
                        
                except sqlite3.OperationalError as e:
                    if "database is locked" in str(e) or "access" in str(e).lower():
                        attempt += 1
                        if attempt >= max_attempts:
                            logger.error(f"Failed to access database after {max_attempts} attempts")
                            raise Exception(f"Failed to access database: {str(e)}")
                        else:
                            logger.warning(f"Database locked, retrying ({attempt}/{max_attempts})")
                            import time
                            time.sleep(1)
                    else:
                        # If it's not a locking issue, re-raise immediately
                        raise
                        
        except Exception as e:
            logger.error(f"Failed to initialize database: {str(e)}")
            raise Exception(f"Failed to initialize database: {str(e)}")

    def add_user(self, name, email):
        """Add a new user to the database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO users (name, email, created_at) VALUES (?, ?, ?)",
                    (name, email, datetime.now().isoformat())
                )
                conn.commit()
                return cursor.lastrowid
        except Exception as e:
            logger.error(f"Failed to add user: {str(e)}")
            raise

    def populate_default_settings(self):
        """Populate all tables with default settings"""
        
        # 1. Populate SMTP settings
        smtp_settings = [
            ('max_retries', '3', 'integer', 'Maximum number of SMTP connection attempts'),
            ('timeout', '10', 'integer', 'SMTP connection timeout in seconds'),
            ('retry_delay', '2', 'integer', 'Delay between SMTP connection retries in seconds'),
            ('test_sender', 'test@domain.com', 'string', 'Email address used for SMTP testing'),
            ('hello_command', 'HELLO', 'string', 'SMTP greeting command (HELLO/HELO)'),
            ('pool_size', '5', 'integer', 'Size of the SMTP connection pool') 
        ]
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.executemany("""
                INSERT OR IGNORE INTO smtp_settings (setting_name, value, data_type, description)
                VALUES (?, ?, ?, ?)
            """, smtp_settings)
            
            # 2. Populate SMTP ports
            smtp_ports = [
                (25, 1, 1),
                (587, 2, 1),
                (465, 3, 1)
            ]
            cursor.executemany("""
                INSERT OR IGNORE INTO smtp_ports (port, priority, enabled)
                VALUES (?, ?, ?)
            """, smtp_ports)
        
            # 3. Populate rate limits
            rate_limits = [
                ('smtp_vrfy', '5', '60', 'Rate limit for SMTP VRFY commands'),
                ('smtp_connection', '10', '60', 'Rate limit for SMTP connection attempts'),
                ('dns_lookup', '20', '60', 'Rate limit for DNS lookups'),
                ('default', '10', '60', 'Default rate limit for operations')
            ]
            
            cursor.executemany("""
                INSERT OR IGNORE INTO rate_limits (operation, max_requests, time_window, description)
                VALUES (?, ?, ?, ?)
            """, rate_limits)
            
            # 4. Populate validation scoring
            validation_scoring = [
                ('valid_format', 20, 0, 'Email has valid format'),
                ('not_disposable', 10, 0, 'Email is not from a disposable provider'),
                ('disposable', 10, 1, 'Email is from a disposable provider'),
                ('blacklisted', 15, 1, 'Domain is blacklisted'),
                ('mx_records', 20, 0, 'Domain has valid MX records'),
                ('spf_found', 5, 0, 'Domain has SPF record'),
                ('dkim_found', 5, 0, 'Domain has DKIM record'),
                ('smtp_connection', 30, 0, 'SMTP connection successful'),
                ('catch_all', 15, 1, 'Domain accepts catch-all emails'),
                ('no_catch_all', 15, 0, 'Domain does not accept catch-all emails'),
                ('vrfy_confirmed', 10, 0, 'VRFY command confirms email'),
                ('imap_available', 5, 0, 'IMAP service available'),
                ('pop3_available', 5, 0, 'POP3 service available')
            ]
            
            cursor.executemany("""
                INSERT OR IGNORE INTO validation_scoring (check_name, score_value, is_penalty, description)
                VALUES (?, ?, ?, ?)
            """, validation_scoring)
            
            # 5. Populate confidence levels
            confidence_levels = [
                ('Very High', 90, 100, 'Email almost certainly exists'),
                ('High', 70, 89, 'Email very likely exists'),
                ('Medium', 50, 69, 'Email probably exists'),
                ('Low', 30, 49, 'Email may exist but verification is uncertain'),
                ('Very Low', 0, 29, 'Email likely doesnt exist')
            ]
            
            cursor.executemany("""
                INSERT OR IGNORE INTO confidence_levels (level_name, min_threshold, max_threshold, description)
                VALUES (?, ?, ?, ?)
            """, confidence_levels)
            
            # 6. Populate thread pool settings
            thread_pool_settings = [
                ('max_worker_threads', 10, 'Maximum number of worker threads for parallel email validation'),
                ('connection_timeout', 15, 'Connection timeout in seconds'),
                ('thread_idle_timeout', 60, 'How long to keep idle threads alive')
            ]
            
            cursor.executemany("""
                INSERT OR IGNORE INTO thread_pool_settings (setting_name, value, description)
                VALUES (?, ?, ?)
            """, thread_pool_settings)
            
            # 7. Populate cache settings
            cache_settings = [
                ('mx_record', 1000, 3600, 60, 'MX record lookup cache'),
                ('ttl_cache', 128, 600, 60, 'General TTL cache for function results')
            ]
            
            cursor.executemany("""
                INSERT OR IGNORE INTO cache_settings (cache_name, max_size, ttl_seconds, cleanup_interval, description)
                VALUES (?, ?, ?, ?, ?)
            """, cache_settings)
            
            # 8. Populate DNS settings
            dns_settings = [
                ('timeout', '10', 'integer', 'DNS resolution timeout in seconds'),
                ('nameservers', '8.8.8.8,1.1.1.1', 'string', 'Comma-separated list of DNS nameservers'),
                ('use_a_record_fallback', 'true', 'boolean', 'Use A record as fallback when MX record is not found'),
                ('dkim_selector', 'default', 'string', 'DKIM selector to use for DKIM checks')
            ]
            
            cursor.executemany("""
                INSERT OR IGNORE INTO dns_settings (setting_name, value, data_type, description)
                VALUES (?, ?, ?, ?)
            """, dns_settings)
            
            # 9. Populate IMAP settings
            imap_settings = [
                ('port', '993', 'integer', 'Default IMAP SSL port'),
                ('timeout', '5', 'integer', 'IMAP connection timeout in seconds')
            ]
            
            cursor.executemany("""
                INSERT OR IGNORE INTO imap_settings (setting_name, value, data_type, description)
                VALUES (?, ?, ?, ?)
            """, imap_settings)
            
            # 10. Populate POP3 settings
            pop3_settings = [
                ('port', '995', 'integer', 'Default POP3 SSL port'),
                ('timeout', '5', 'integer', 'POP3 connection timeout in seconds')
            ]
            
            cursor.executemany("""
                INSERT OR IGNORE INTO pop3_settings (setting_name, value, data_type, description)
                VALUES (?, ?, ?, ?)
            """, pop3_settings)
            
            # 11. Populate app_settings
            app_settings = [
                ('general', 'user_agent', 'EmailVerificationScript (https://github.com/Ranrar/EVS)', 'string', 'User-Agent string for HTTP requests'),
                ('general', 'log_display_limit', '50', 'integer', 'Maximum number of log entries to display (0 for unlimited)'),
                ('general', 'created_at', datetime.now().isoformat(), 'datetime', 'When the database was created'),
                ('general', 'last_updated', datetime.now().isoformat(), 'datetime', 'When the database was last updated'),
                ('general', 'version', '1.0.0', 'string', 'EVS version'),
                ('rate_limiter', 'rate_limit_requests', '10', 'integer', 'Default maximum requests allowed within time window'),
                ('rate_limiter', 'rate_limit_window', '60', 'integer', 'Default time window in seconds')
            ]
            
            cursor.executemany("""
                INSERT OR IGNORE INTO app_settings (category, name, value, data_type, description)
                VALUES (?, ?, ?, ?, ?)
            """, app_settings)
                
            # 12. Populate blacklisted_domains
            blacklisted_domains = [
                ('blacklisted.com', 'Spamhaus', datetime.now().isoformat()),
                ('blacklisted.com', 'Barracuda', datetime.now().isoformat()),
                ('blacklisted.com', 'SpamCop', datetime.now().isoformat()),
                ('baddomain.net', 'Spamhaus', datetime.now().isoformat()),
                ('baddomain.net', 'SORBS', datetime.now().isoformat()),
                ('malicious.org', 'SpamCop', datetime.now().isoformat()),
                ('malicious.org', 'Spamhaus', datetime.now().isoformat())
            ]
            
            cursor.executemany("""
                INSERT OR IGNORE INTO blacklisted_domains (domain, source, added_date)
                VALUES (?, ?, ?)
            """, blacklisted_domains)
            
            # 13. Populate disposable_domains
            disposable_domains = [
                ('mailinator.com', datetime.now().isoformat()),
                ('10minutemail.com', datetime.now().isoformat()),
                ('tempmail.com', datetime.now().isoformat()),
                ('temp-mail.org', datetime.now().isoformat()),
                ('guerrillamail.com', datetime.now().isoformat()),
                ('dispostable.com', datetime.now().isoformat()),
                ('yopmail.com', datetime.now().isoformat()),
                ('getnada.com', datetime.now().isoformat()),
                ('tempinbox.com', datetime.now().isoformat())
            ]
            
            cursor.executemany("""
                INSERT OR IGNORE INTO disposable_domains (domain, added_date)
                VALUES (?, ?)
            """, disposable_domains)
                
            # 14. Populate log_columns
            email_records_field_definitions = [
                ('id', '#', 'METADATA', 0, 1, 'Record ID'),
                ('timestamp', 'Timestamp', 'METADATA', 1, 1, 'Timestamp'),
                ('email', 'Email Address', 'CORE', 2, 1, 'Email address being validated'),
                ('domain', 'Domain', 'CORE', 3, 0, 'Domain part of email address'),
                ('smtp_result', 'Verified result', 'CORE', 4, 1, 'Result of validation'),
                ('error_message', 'Error Message', 'CORE', 5, 0, 'Error message if validation failed'),
                ('disposable', 'Disposable', 'SECURITY', 6, 0, 'Whether email is from a disposable provider'),
                ('spf_status', 'SPF Status', 'SECURITY', 7, 0, 'SPF record status'),
                ('dkim_status', 'DKIM Status', 'SECURITY', 8, 0, 'DKIM record status'),
                ('blacklist_info', 'Blacklist Info', 'SECURITY', 9, 0, 'Blacklist status'),
                ('mx_record', 'MX Record', 'TECHNICAL', 10, 0, 'MX server information'),
                ('port', 'Port', 'TECHNICAL', 11, 1, 'SMTP port used'),
                ('mx_ip', 'MX IP', 'TECHNICAL', 12, 0, 'IP address of mail server'),
                ('mx_preferences', 'MX Preferences', 'TECHNICAL', 13, 0, 'MX record priority'),
                ('smtp_banner', 'SMTP Banner', 'TECHNICAL', 14, 0, 'SMTP server information'),
                ('smtp_vrfy', 'SMTP VRFY', 'TECHNICAL', 15, 0, 'SMTP VRFY command result'),
                ('catch_all', 'Catch All', 'TECHNICAL', 16, 0, 'Whether domain accepts catch-all emails'),
                ('imap_status', 'IMAP Status', 'PROTOCOL', 17, 0, 'IMAP availability'),
                ('imap_info', 'IMAP Info', 'PROTOCOL', 18, 0, 'IMAP server details'),
                ('pop3_status', 'POP3 Status', 'PROTOCOL', 19, 0, 'POP3 availability'),
                ('pop3_info', 'POP3 Info', 'PROTOCOL', 20, 0, 'POP3 server details'),
                ('server_policies', 'Server Policies', 'SECURITY', 21, 1, 'Email server policies'),
                ('confidence_score', 'Confidence Score', 'CORE', 22, 1, 'Email validation confidence score'),
                ('execution_time', 'Execution Time', 'METADATA', 23, 1, 'Execution time in seconds'),
                ('check_count', 'Check Count', 'METADATA', 24, 1, 'Number of times email was checked')
            ]
            
            cursor.executemany("""
                INSERT OR IGNORE INTO email_records_field_definitions (name, display_name, category, display_index, visible, description)
                VALUES (?, ?, ?, ?, ?, ?)
            """,email_records_field_definitions)
            
            logger.info("All default settings populated successfully")

    def run_installation(self):
        """Run the full installation process"""
        try:
            logger.info("Running installation process")
            
            # Database structure should already be initialized in __init__
            # Make sure the user was created successfully
            if not self._initialized:
                logger.error("Installer not properly initialized")
                return False
                
            # Set the first user as active
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE users SET is_active = 1 WHERE id = 1")
                conn.commit()
                
            logger.info("Installation completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Installation failed: {str(e)}")
            return False
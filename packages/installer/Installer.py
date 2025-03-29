import sys
import subprocess
import os
import sqlite3
from datetime import datetime
from typing import Any, Dict
import urwid
from packages.logger.logger import P_Log, DEFAULT_LOGGER_NAME

# Use the default name for your singleton logger factory
def get_logger(name=DEFAULT_LOGGER_NAME, to_console=False):
    if not hasattr(get_logger, 'instances'):
        get_logger.instances = {}
    
    if name not in get_logger.instances:
        get_logger.instances[name] = P_Log(logger_name=name, log_to_console=to_console)
    
    return get_logger.instances[name]

# Get a singleton logger instance - no need to specify name
logger = get_logger(to_console=False)  # Uses DEFAULT_LOGGER_NAME by default

# First check for dependencies
logger.info("Checking for required dependencies...")
required_dependencies = ["urwid", "dns", "requests", "tabulate", "sqlite3"]
missing_dependencies = []

for dep in required_dependencies:
    try:
        __import__(dep)
        logger.debug(f"Dependency check: {dep} is installed")
    except ImportError:
        missing_dependencies.append(dep)
        logger.warning(f"Dependency check: {dep} is missing")

if missing_dependencies:
    logger.warning(f"Missing dependencies: {', '.join(missing_dependencies)}")
    print("Missing dependencies: " + ", ".join(missing_dependencies))
    choice = input("Do you want to install them? (Y/N): ")
    if choice.lower() in ["y", "yes"]:
        logger.info(f"User chose to install missing dependencies")
        try:
            # Path to local requirements.txt
            req_path = os.path.join(os.getcwd(), 'packages', 'installer', 'requirements.txt')
            dep_path = os.path.join(os.getcwd(), 'packages', 'installer', 'dependencies')
            
            if os.path.exists(req_path) and os.path.exists(dep_path):
                logger.info(f"Installing from local dependencies folder: {dep_path}")
                print(f"Installing from local dependencies folder...")
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install", "--user", "--no-index", 
                     "--find-links", dep_path, "-r", req_path]
                )
            else:
                logger.info("Local dependencies not found, installing from PyPI...")
                print("Local dependencies not found, installing from PyPI...")
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install", "--user", *missing_dependencies]
                )
            print("Dependencies installed successfully. Please restart the script.")
            logger.info("Dependencies installed successfully")
        except Exception as e:
            print("Error installing dependencies:", e)
            logger.error(f"Error installing dependencies: {e}")
    else:
        logger.info("User declined to install dependencies, exiting")
    sys.exit(0)
else:
    logger.info("All required dependencies are installed")

def clear_screen():
    """Clear the console screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

class Installer:
    # Class-level variables for singleton pattern
    _instance = None
    _initialized = False
    _license_accepted = False
    
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
        
        # Set first run flag - but don't create directory yet
        self.first_run = not os.path.exists(self.db_path)
        
        if self.first_run:
            self._show_license_agreement()
        else:
            logger.info(f"Using existing database at {self.db_path}")
            self._initialized = True
    
    def _show_license_agreement(self):
        """Show license agreement and wait for acceptance before proceeding"""
        ui = InstallerUI(self)
        ui.start()
        
        # Check if license was declined and exit the program if so
        if not self._license_accepted:
            logger.info("License was declined - exiting application")
            import sys
            sys.exit(0)  # Exit the entire Python process
    
    def setup_database_after_license_acceptance(self):
        """This method is called after license is accepted"""
        logger.info("License accepted, proceeding with user information")
        self._license_accepted = True
        
        # Only set the license flag but don't create the directory yet
        # We'll create it after user info is submitted
        
        # Mark as initialized for the UI flow
        self._initialized = True
        
    def _initialize_new_database(self):
        """Initialize a new database with user information using urwid UI"""
        # This method is now only called after license acceptance
        if not self._license_accepted:
            logger.warning("Attempted to initialize database without license acceptance")
            return
            
        logger.info("Initializing new database")
        # Rest of database initialization can happen here
        
    # Rest of your class methods remain the same
    def init_database(self):
        """Initialize the database"""
        if not self._license_accepted:
            logger.warning("Attempted to init database without license acceptance")
            return False
            
        try:
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
                        execution_time REAL DEFAULT 0,
                        batch_id INTEGER
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
                        conn.execute("""
CREATE TABLE IF NOT EXISTS batch_info (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    source TEXT,
    created_at TEXT NOT NULL,
    completed_at TEXT,
    total_emails INTEGER DEFAULT 0,
    processed_emails INTEGER DEFAULT 0,
    success_count INTEGER DEFAULT 0,
    failed_count INTEGER DEFAULT 0,
    status TEXT DEFAULT 'queued',
    error_message TEXT,
    settings_snapshot TEXT
)
""")
                        conn.execute("""
CREATE TABLE IF NOT EXISTS temp_blocked_domains (
    domain TEXT PRIMARY KEY,
    blocked_until TEXT,
    reason TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
""")
                        conn.execute("""
CREATE TABLE IF NOT EXISTS batch_info_field_definitions (
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
        if not self._license_accepted:
            logger.warning("Attempted to add user without license acceptance")
            return None
            
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
        if not self._license_accepted:
            logger.warning("Attempted to populate settings without license acceptance")
            return False
            
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
                ('nameservers', '8.8.8.8,8.8.4.4,1.1.1.1,1.0.0.1,9.9.9.9,9.9.9.10,149.112.112.112,208.67.222.222,208.67.220.220,64.6.64.6,64.6.65.6', 'string', 'Comma-separated list of DNS nameservers'),
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
                ('general', 'log_display_limit', '100', 'integer', 'Maximum number of log entries to display (0 for unlimited)'),
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

            # Add this to the populate_default_settings method alongside other field definitions
            batch_info_field_definitions = [
                ('id', 'ID', 'METADATA', 0, 1, 'Batch ID'),
                ('name', 'Name', 'CORE', 1, 1, 'Batch name or description'),
                ('source', 'Source', 'METADATA', 2, 1, 'Source of the email addresses'),
                ('created_at', 'Created', 'METADATA', 3, 1, 'When the batch was created'),
                ('completed_at', 'Completed', 'METADATA', 4, 1, 'When the batch was completed'),
                ('total_emails', 'Total', 'STATISTICS', 5, 1, 'Total email count'),
                ('processed_emails', 'Processed', 'STATISTICS', 6, 1, 'Processed email count'),
                ('success_count', 'Success', 'STATISTICS', 7, 1, 'Successfully validated count'),
                ('failed_count', 'Failed', 'STATISTICS', 8, 1, 'Failed validation count'),
                ('status', 'Status', 'CORE', 9, 1, 'Batch status'),
                ('error_message', 'Error', 'METADATA', 10, 0, 'Error message if batch failed'),
                ('settings_snapshot', 'Settings', 'METADATA', 11, 0, 'Settings used for batch')
            ]

            cursor.executemany("""
                INSERT OR IGNORE INTO batch_info_field_definitions (name, display_name, category, display_index, visible, description)
                VALUES (?, ?, ?, ?, ?, ?)
            """, batch_info_field_definitions)
            
            logger.info("All default settings populated successfully")

    def run_installation(self):
        """Run the full installation process"""
        try:

            # Make sure the user was created successfully
            if not self._initialized:
                logger.error("Installer not properly initialized")
                return False
                
            # Set the first user as active
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE users SET is_active = 1 WHERE id = 1")
                conn.commit()
                
            return True
            
        except Exception as e:
            logger.error(f"Installation failed: {str(e)}")
            return False

# Add this class for consistent button styling
class NoCursorSelectableIcon(urwid.SelectableIcon):
    def get_cursor_coords(self, size):
        # Always return None so no cursor is drawn
        return None

class PlainButton(urwid.Button):
    button_left = urwid.Text("")
    button_right = urwid.Text("")
    
    def __init__(self, label, on_press=None, user_data=None):
        super().__init__("", on_press, user_data)
        # Use NoCursorSelectableIcon instead of default SelectableIcon
        self._w = urwid.AttrMap(NoCursorSelectableIcon(str(label)), None, focus_map='menu_focus')

def apply_box_style(content, title="Email Verification Script"):
    """Apply consistent LineBox styling to any content"""
    boxed_content = urwid.LineBox(content, title=title)
    return urwid.Padding(boxed_content)

def license_agreement_dialog(on_accept, on_decline):
    
    # Read license from LICENSE file - no fallback
    license_path = os.path.join(os.getcwd(), 'LICENSE')
    try:
        with open(license_path, 'r') as license_file:
            license_text = license_file.read()
            logger.info(f"License text loaded from {license_path}")
    except Exception as e:
        # If file can't be read, log error and raise exception
        error_msg = f"ERROR: Could not read LICENSE file: {str(e)}"
        logger.error(error_msg)
        raise FileNotFoundError(f"LICENSE file required but not found or not readable: {error_msg}")
    
    # Create the license text widget
    license_text_widget = urwid.Text(license_text)
    
    # Create scrollable content area for the license text with controlled width
    license_walker = urwid.SimpleListWalker([license_text_widget])
    license_listbox = urwid.ListBox(license_walker)
    
    # Control the width using a fixed width container
    license_box = urwid.BoxAdapter(license_listbox, 16)  # Height of 15 lines
    fixed_width_box = urwid.Padding(
        license_box,
        width=60,  # Fixed width of 60 columns
        align='center',
        left=2,  # Additional padding on the left
        right=2  # Additional padding on the right
    )
    
    # Add a frame around the license text
    framed_license = urwid.LineBox(fixed_width_box, title="License Agreement")
    
    # Create accept and decline buttons
    accept_button = PlainButton("Accept")
    decline_button = PlainButton("Decline")
    
    # Connect signals to buttons
    urwid.connect_signal(accept_button, 'click', on_accept)
    urwid.connect_signal(decline_button, 'click', on_decline)
    
    # Style the buttons - matching the confirmation dialog style
    accept_btn = urwid.AttrMap(accept_button, None, focus_map="menu_focus")
    decline_btn = urwid.AttrMap(decline_button, None, focus_map="menu_focus")
    
    # Create button row with padding between buttons
    button_row = urwid.Columns([
        ('weight', 1, urwid.Text("")),
        ('pack', accept_btn),
        ('fixed', 3, urwid.Text(" ")),  # Space between buttons
        ('pack', decline_btn),
        ('weight', 1, urwid.Text(""))
    ])
    
    # Set focus to the accept button in the button row
    button_row.focus_position = 1  # Position of accept_btn
    
    # Make sure the button row also respects our width constraints
    button_row_padded = urwid.Padding(
        button_row,
        width=60,  # Fixed width of 60 columns
        align='center'
    )
    
    # Combine license and buttons into a pile
    dialog_pile = urwid.Pile([
        framed_license,  # Use the framed license text
        urwid.Divider(),
        button_row_padded,  # Use the width-constrained button row
        urwid.Divider()
    ])
    
    # Set focus to the button row in the pile
    dialog_pile.focus_position = 2  # Position of button_row
    
    # Create a dialog box
    dialog = urwid.Filler(dialog_pile, 'middle')
    
    # Final padding to ensure the overall dialog has the desired width
    padded_dialog = urwid.Padding(
        dialog,
        width=64,  # Slightly wider than the content to accommodate the frame
        align='center'
    )
    
    return apply_box_style(padded_dialog, title="Email Verification Script - Installer")

# Modify the EnterEdit class to enforce specific character limits
class EnterEdit(urwid.Edit):
    """An Edit widget that calls a function when Enter is pressed and enforces character limits"""
    
    def __init__(self, caption="", edit_text="", multiline=False, on_enter=None, min_length=None, max_length=None):
        super().__init__(caption, edit_text, multiline)
        self.on_enter = on_enter
        self.min_length = min_length
        self.max_length = max_length
        
    def keypress(self, size, key):
        if key == 'enter' and self.on_enter:
            return self.on_enter()
        
        # Enforce maximum length by ignoring character input when at max
        if self.max_length is not None:
            if len(self.edit_text) >= self.max_length and key not in ('backspace', 'delete', 'left', 'right', 'up', 'down', 'home', 'end'):
                # Only ignore character insertion, not navigation keys
                if len(key) == 1:
                    return
        
        return super().keypress(size, key)

def user_info_form(on_submit, on_cancel=None, name_value="", email_value="", focus_field="name"):
    """Create a form to collect user information with Enter key support and character limits"""
    
    # Function to validate name before moving to email field
    def on_name_enter():
        if len(name_edit.edit_text.strip()) < 3:
            # Don't allow moving to next field if name is too short
            return True
        form_pile.focus_position = 2  # Focus on email field
        return True
    
    # Function to validate both fields before submitting
    def on_email_enter():
        # Validation will be done in on_submit
        on_submit(name_edit.edit_text, email_edit.edit_text)
        return True
    
    # Create edit fields without captions
    name_edit = EnterEdit("", edit_text=name_value, on_enter=on_name_enter, min_length=3, max_length=32)
    email_edit = EnterEdit("", edit_text=email_value, on_enter=on_email_enter, max_length=255)
    
    # Create rows with explicit label and edit field side by side
    name_row = urwid.Columns([
        ('fixed', 7, urwid.Text("Name:")),
        ('weight', 1, urwid.AttrMap(name_edit, "edit_unfocused", focus_map="edit_focused")),
    ])
    
    email_row = urwid.Columns([
        ('fixed', 7, urwid.Text("Email:")),
        ('weight', 1, urwid.AttrMap(email_edit, "edit_unfocused", focus_map="edit_focused")),
    ])
    
    # Create submit and cancel buttons
    submit_button = PlainButton("Submit")
    cancel_button = PlainButton("Cancel")
    
    # Connect signals
    urwid.connect_signal(submit_button, 'click', 
                         lambda button: on_submit(name_edit.edit_text, email_edit.edit_text))
    if on_cancel:
        urwid.connect_signal(cancel_button, 'click', on_cancel)
    
    # Style the buttons
    submit_btn = urwid.AttrMap(submit_button, None, focus_map="menu_focus")
    cancel_btn = urwid.AttrMap(cancel_button, None, focus_map="menu_focus")
    
    # Create button row
    button_row = urwid.Columns([
        ('weight', 1, urwid.Text("")),
        ('pack', submit_btn),
        ('fixed', 3, urwid.Text(" ")),  # Space between buttons
        ('pack', cancel_btn),
        ('weight', 1, urwid.Text(""))
    ])
    
    # Create form layout - without extra dividers
    form_pile = urwid.Pile([
        name_row,
        urwid.Divider(" ", top=0, bottom=0),  # Minimal spacing
        email_row,
        urwid.Divider(" ", top=0, bottom=0),  # Minimal spacing
        button_row,
    ])
    
    # Set focus based on which field needs attention - adjusted positions
    if focus_field == "name":
        form_pile.focus_position = 0  # Position of name_row
    elif focus_field == "email":
        form_pile.focus_position = 2  # Position of email_row
    elif focus_field == "submit":
        form_pile.focus_position = 4  # Position of button_row
    
    # Create a padding with fixed width but minimal left/right margins
    # and pack the height to keep it tight
    form_padding = urwid.Padding(
        form_pile,
        width=('relative', 95),  # Use 95% of the available width
        align='center',
        left=2,  # Minimal padding on the left
        right=2   # Minimal padding on the right
    )
    
    # Add left/right/top/bottom padding to create spacing inside the frame
    padded_pile = urwid.Padding(
        urwid.Pile([
            urwid.Divider(" ", top=0, bottom=0),  # Minimal top margin
            form_padding,
            urwid.Divider(" ", top=0, bottom=0)   # Minimal bottom margin
        ]),
        left=1, right=1
    )
    
    # Create a LineBix with the compact form
    framed_form = urwid.LineBox(padded_pile, title="Please enter your user information:")
    
    # Create a tight container that doesn't expand to fill the screen
    container = urwid.Filler(
        urwid.Padding(
            framed_form,
            width=('relative', 50),  # Use 50% of the screen width
            align='center'
        ),
        valign='middle'
    )
    
    return apply_box_style(container, title="Email Verification Script - Installer")

def show_error_message(message, on_ok):
    """Display an error message with an OK button"""
    
    # Create the error text
    error_text = urwid.Text(message, align='center')
    
    # Create OK button
    ok_button = PlainButton("OK")
    urwid.connect_signal(ok_button, 'click', on_ok)
    
    # Style the button
    ok_btn = urwid.AttrMap(ok_button, None, focus_map="menu_focus")
    
    # Button container
    button_container = urwid.Columns([
        ('weight', 1, urwid.Text("")),
        ('pack', ok_btn),
        ('weight', 1, urwid.Text(""))
    ])
    
    # Create the message layout
    message_pile = urwid.Pile([
        urwid.Divider(),
        error_text,
        urwid.Divider(),
        button_container,
        urwid.Divider()
    ])
    
    # Create the message container
    message_box = urwid.Filler(message_pile, 'middle')
    
    return apply_box_style(message_box, title="User Information")

def success_message(message, on_continue):
    """Display a success message with a Continue button"""
    
    # Create the success text
    success_text = urwid.Text(message, align='center')
    
    # Create Continue button
    continue_button = PlainButton("Continue")
    urwid.connect_signal(continue_button, 'click', on_continue)
    
    # Style the button
    continue_btn = urwid.AttrMap(continue_button, None, focus_map="menu_focus")
    
    # Button container
    button_container = urwid.Columns([
        ('weight', 1, urwid.Text("")),
        ('pack', continue_btn),
        ('weight', 1, urwid.Text(""))
    ])
    
    # Create the message layout
    message_pile = urwid.Pile([
        urwid.Divider(),
        success_text,
        urwid.Divider(),
        button_container,
        urwid.Divider()
    ])
    
    # Create the message container
    message_box = urwid.Filler(message_pile, 'middle')
    
    return apply_box_style(message_box, title="Success")

def create_centered_overlay(content, background=None):
    """
    Create a centered overlay for any content widget.
    
    Args:
        content: The widget to be displayed in the center
        background: Background widget (defaults to medium shade)
        
    Returns:
        An Overlay widget with the content centered on the screen
    """
    if background is None:
        background = urwid.SolidFill("\N{MEDIUM SHADE}")
        
    return urwid.Overlay(
        content,
        background,
        align=urwid.CENTER,
        width=('relative', 80),
        valign=urwid.MIDDLE,
        height=('relative', 30),
        min_width=80,
        min_height=30
    )

class InstallerUI:
    def __init__(self, installer_instance):
        self.installer = installer_instance
        self.loop = None
        self.name_value = ""  # Store the user-entered name
        self.email_value = ""  # Store the user-entered email
        
    def start(self):
        """Start the installer UI"""
        
        # Setup the initial view with license agreement
        initial_view = license_agreement_dialog(
            self.on_license_accept,
            self.on_license_decline
        )
        
        top = create_centered_overlay(initial_view)
        
        # Start the main loop with the same palette as main.py
        self.loop = urwid.MainLoop(
            top,
            palette=[
                ("reversed", "standout", ""),
                ("menu_focus", "white", "dark red"),
                ("edit_unfocused", "black", "light gray"),
                ("edit_focused", "black", "light gray"),
                ("button", "black", "light gray"),
                ("error", "white", "dark red")
            ],
            unhandled_input=self.global_keypress
        )
        
        try:
            self.loop.run()
        except Exception as e:
            logger.error(f"Error in installer UI: {e}")
            
    def global_keypress(self, key):
        """Handle global keypresses"""
        if key in ('q', 'Q', 'esc'):
            self.on_license_decline(None)
            return True
        return False
    
    def exit_program(self):
        """Exit the installer with cleanup"""
        # Clear any references that might cause cycles
        self.loop.widget = None
        self.loop = None
        raise urwid.ExitMainLoop()
        
    def on_license_accept(self, button):
        
        # Now we can proceed with database setup
        self.installer.setup_database_after_license_acceptance()
        
        # Show the user info form
        self.show_user_form()
        
    def on_license_decline(self, button):
        """Handle license decline"""
        
        # Show a message and exit
        exit_msg = "License not accepted. Installation cancelled."        
        # Change the view to show the exit message
        exit_view = show_error_message(exit_msg, lambda button: self.exit_program())
        self.loop.widget = create_centered_overlay(exit_view)
        
    def show_user_form(self, focus_field="name"):
        """Show the user information form with previously entered values"""
        user_form = user_info_form(
            self.on_user_form_submit,
            self.on_user_form_cancel,
            name_value=self.name_value,
            email_value=self.email_value,
            focus_field=focus_field
        )
        
        self.loop.widget = create_centered_overlay(user_form)
        
    def on_user_form_submit(self, name, email):
        """Handle user form submission with character limit validation"""
        # Save the entered values
        self.name_value = name
        self.email_value = email
        
        # Validate input
        if not name.strip():
            self.show_error("Name cannot be empty.", focus_field="name")
            return
            
        # Validate name length (3-32 characters)
        if len(name.strip()) < 3:
            self.show_error("Name must be at least 3 characters.", focus_field="name")
            return
            
        if len(name.strip()) > 32:
            self.show_error("Name cannot exceed 32 characters.", focus_field="name")
            return
            
        # Validate email format and length
        if not '@' in email or not '.' in email:
            self.show_error("Please enter a valid email address.", focus_field="email")
            return
            
        if len(email) > 255:
            self.show_error("Email address is too long (maximum 255 characters).", focus_field="email")
            return
            
        logger.info(f"User information submitted: {name, email}")
        
        # Proceed with database initialization
        try:
            # Create DB directory now that user info is validated
            if not os.path.exists(self.installer.db_dir):
                logger.info(f"Creating database directory: {self.installer.db_dir}")
                os.makedirs(self.installer.db_dir)
            
            # Initialize database structure
            self.installer.init_database()
            
            # Add initial user
            self.installer.add_user(name, email)
            
            # Populate default settings
            self.installer.populate_default_settings()
            
            # Run final installation steps
            self.installer.run_installation()
            
            # Show success message
            self.show_success()
            
        except Exception as e:
            logger.error(f"Error during database initialization: {e}")
            self.show_error(f"Error: {str(e)}", focus_field="name")
            
    def on_user_form_cancel(self, button):
        """Handle user form cancellation with thorough cleanup"""
        logger.info("User form cancelled")
        
        # Reset input storage
        self.name_value = ""
        self.email_value = ""
        
        # Reset installer state
        self.installer._license_accepted = False
        self.installer._initialized = False
        
        # Check for partially created database file and remove it
        if os.path.exists(self.installer.db_path):
            try:
                os.remove(self.installer.db_path)
                logger.info(f"Removed partial database file: {self.installer.db_path}")
            except Exception as e:
                logger.error(f"Failed to remove database file: {str(e)}")
        
        # If the database directory was created, remove it
        if os.path.exists(self.installer.db_dir):
            try:
                # First check if it's empty
                if not os.listdir(self.installer.db_dir):
                    os.rmdir(self.installer.db_dir)
                    logger.info(f"Removed empty database directory: {self.installer.db_dir}")
            except Exception as e:
                logger.error(f"Failed to remove database directory: {str(e)}")
        
        # Go back to license agreement
        initial_view = license_agreement_dialog(
            self.on_license_accept,
            self.on_license_decline
        )
        
        self.loop.widget = create_centered_overlay(initial_view)
        
    def show_error(self, message, focus_field="name"):
        """Show an error message and return to form with focus on specified field"""
        error_view = show_error_message(
            message,
            lambda button: self.show_user_form(focus_field=focus_field)  # Return to form with proper focus
        )
        
        self.loop.widget = create_centered_overlay(error_view)
        
    def show_success(self):
        """Show installation success message"""
        success_view = success_message(
            "Installation completed successfully!\n\nYour database has been initialized with the provided information.",
            lambda button: self.exit_program()
        )
        
        self.loop.widget = create_centered_overlay(success_view)
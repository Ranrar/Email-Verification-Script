import sqlite3
import os
import sys
from datetime import datetime
import logging
import json
from typing import Any, Dict, List, Union

# Configure logger with more detailed logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('database.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def clear_screen():
    """Clear the console screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

class Database:
    # Class-level variables for singleton pattern
    _instance = None
    _initialized = False
    
    def __new__(cls, config=None):
        if cls._instance is None:
            cls._instance = super(Database, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, config=None):
        """Initialize database with optional config"""
        if self._initialized:
            return
            
        # Basic attributes
        self.db_dir = os.path.join(os.getcwd(), 'DB')
        self.db_path = os.path.join(self.db_dir, 'EVS.db')
        self.config = config
        self.current_user = None
        
        # Create DB directory if needed
        if not os.path.exists(self.db_dir):
            os.makedirs(self.db_dir)
        
        # Set first run flag
        self.first_run = not os.path.exists(self.db_path)
        
        if self.first_run:
            self._initialize_new_database()
        
        self._initialized = True

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
        
        # Removed alias input
        
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
            print("\nDatabase and user profile created successfully!\n")
            
        except Exception as e:
            print(f"\nError creating database: {str(e)}")
            # Clean up if anything fails
            if os.path.exists(self.db_path):
                os.remove(self.db_path)

    def init_database(self):
        """Initialize the database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Create email_logs table
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS email_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        email TEXT NOT NULL,
                        domain TEXT NOT NULL,
                        result TEXT,
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
                        check_count INTEGER DEFAULT 1
                    )
                """)
                
                # Create user_info table without alias column
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS user_info (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL,
                        email TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    )
                """)
                conn.commit()
        except Exception as e:
            raise Exception(f"Failed to initialize database: {str(e)}")

    def log_check(self, data):
        """Log an email check with counter for duplicates"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Ensure email is a string and properly formatted
                email = str(data.get('email', '')).strip()
                
                # Check if this email already exists
                cursor.execute("SELECT id, check_count FROM email_logs WHERE email = ?", (email,))
                existing = cursor.fetchone()
                
                if existing:
                    # Email exists - update record and increment counter
                    record_id, current_count = existing
                    new_count = current_count + 1
                    
                    cursor.execute("""
                        UPDATE email_logs SET
                        timestamp = ?,
                        domain = ?,
                        result = ?,
                        error_message = ?,
                        disposable = ?,
                        spf_status = ?,
                        dkim_status = ?,
                        blacklist_info = ?,
                        mx_record = ?,
                        port = ?,
                        mx_ip = ?,
                        mx_preferences = ?,
                        smtp_banner = ?,
                        smtp_vrfy = ?,
                        catch_all = ?,
                        imap_status = ?,
                        imap_info = ?,
                        pop3_status = ?,
                        pop3_info = ?,
                        server_policies = ?,
                        check_count = ?
                        WHERE id = ?
                    """, (
                        data.get('timestamp', datetime.now().strftime("%d-%m-%y %H:%M:%S")),
                        str(data.get('domain', '')),
                        data.get('result', ''),
                        str(data.get('error_message', '')),
                        data.get('disposable', ''),
                        data.get('spf_status', ''),
                        data.get('dkim_status', ''),
                        data.get('blacklist_info', ''),
                        str(data.get('mx_record', '')),
                        data.get('port', ''),
                        data.get('mx_ip', ''),
                        data.get('mx_preferences', ''),
                        str(data.get('smtp_banner', '')),
                        data.get('smtp_vrfy', ''),
                        data.get('catch_all', ''),
                        data.get('imap_status', ''),
                        str(data.get('imap_info', '')),
                        data.get('pop3_status', ''),
                        str(data.get('pop3_info', '')),
                        data.get('server_policies', ''),
                        new_count,
                        record_id
                    ))
                else:
                    # New email - insert with check_count = 1
                    cursor.execute("""
                        INSERT INTO email_logs (
                            timestamp, email, domain, result, error_message,
                            disposable, spf_status, dkim_status, blacklist_info,
                            mx_record, port, mx_ip, mx_preferences, smtp_banner,
                            smtp_vrfy, catch_all, imap_status, imap_info,
                            pop3_status, pop3_info, server_policies, check_count
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        data.get('timestamp', datetime.now().strftime("%d-%m-%y %H:%M:%S")),
                        email,
                        str(data.get('domain', '')),
                        data.get('result', ''),
                        str(data.get('error_message', '')),
                        data.get('disposable', ''),
                        data.get('spf_status', ''),
                        data.get('dkim_status', ''),
                        data.get('blacklist_info', ''),
                        str(data.get('mx_record', '')),
                        data.get('port', ''),
                        data.get('mx_ip', ''),
                        data.get('mx_preferences', ''),
                        str(data.get('smtp_banner', '')),
                        data.get('smtp_vrfy', ''),
                        data.get('catch_all', ''),
                        data.get('imap_status', ''),
                        str(data.get('imap_info', '')),
                        data.get('pop3_status', ''),
                        str(data.get('pop3_info', '')),
                        data.get('server_policies', ''),
                        1  # Initial check count
                    ))
                conn.commit()
                
        except Exception as e:
            logger.error(f"Error in log_check: {e}")
            raise

    def show_logs(self, selected_columns=None, limit=None):
        """Retrieve logs with proper column filtering"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Map column names to database field names
                column_mapping = {
                    "ID": "id",
                    "Time": "timestamp",
                    "Email": "email",
                    "Domain": "domain", 
                    "Result": "result",
                    "Error": "error_message",
                    "Disposable": "disposable",
                    "SPF": "spf_status",
                    "DKIM": "dkim_status",
                    "Blacklist": "blacklist_info",
                    "MX": "mx_record",
                    "Port": "port",
                    "IP": "mx_ip",
                    "MXPref": "mx_preferences",
                    "SMTP": "smtp_banner",
                    "VRFY": "smtp_vrfy",
                    "Catch": "catch_all",
                    "IMAP": "imap_status",
                    "IMAPInfo": "imap_info",
                    "POP3": "pop3_status", 
                    "POP3Info": "pop3_info",
                    "Policies": "server_policies",
                    "Count": "check_count"
                }
                
                # If we have selected columns, use them
                if selected_columns:
                    # Get display names from config
                    display_names = {}
                    if hasattr(self, 'config') and hasattr(self.config, 'LOG_COLUMNS'):
                        for col_name in selected_columns:
                            if col_name in self.config.LOG_COLUMNS:
                                display_names[col_name] = self.config.LOG_COLUMNS[col_name].display_name
                    
                    # Prepare headers and db columns
                    headers = []
                    db_columns = []
                    
                    # Sort by index for consistent ordering
                    for col_name, idx in sorted(selected_columns.items(), key=lambda x: x[1]):
                        if col_name in column_mapping:
                            headers.append(display_names.get(col_name, col_name))
                            db_columns.append(column_mapping[col_name])
                            
                    # Explicitly use the provided limit parameter, falling back to config if available
                    if limit is not None:
                        # Use the explicitly provided limit
                        log_limit = limit
                    elif hasattr(self, 'config') and hasattr(self.config, 'LOG_DISPLAY_LIMIT'):
                        # Use the config's value if available
                        log_limit = self.config.LOG_DISPLAY_LIMIT
                    else:
                        # Default value
                        log_limit = 0
                    
                    # If limit is 0, show all entries (no LIMIT clause)
                    limit_clause = "" if log_limit == 0 else f" LIMIT {log_limit}"
                    
                    query = f"SELECT {', '.join(db_columns)} FROM email_logs ORDER BY id ASC{limit_clause}"
                    logger.debug(f"SQL Query with limit {log_limit}: {query}")
                    
                    cursor.execute(query)
                    rows = cursor.fetchall()
                    
                    return headers, rows
                
                else:
                    # Default columns if none specified
                    db_columns = ["id", "timestamp", "email", "result", "catch_all", "check_count"]
                    headers = ["ID", "Time", "Email", "Result", "Catch-all", "Count"]
                    
                    # Use the limit parameter if provided
                    log_limit = limit if limit is not None else 10
                    limit_clause = "" if log_limit == 0 else f" LIMIT {log_limit}"
                    
                    query = f"SELECT {', '.join(db_columns)} FROM email_logs ORDER BY id ASC{limit_clause}"
                    cursor.execute(query)
                    rows = cursor.fetchall()
                    
                    return headers, rows
                    
        except Exception as e:
            logger.error(f"Error in show_logs: {e}")
            raise

    def clear_logs(self):
        """Clear all logs from the database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM email_logs")
            conn.commit()

    def clear_email_logs(self):
        """Clear all records from the email_logs table"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM email_logs")
                conn.commit()
        except Exception as e:
            logger.error(f"Error clearing email logs: {e}")
            raise

    def add_user(self, name: str, email: str):
        """Add a new user without alias"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO user_info (name, email, created_at)
                VALUES (?, ?, ?)
            """, (
                name,
                email,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ))
            conn.commit()

    def get_users(self):
        """Retrieve user info without decryption"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM user_info ORDER BY name")
            return cursor.fetchall()

    def delete_user(self, user_id: int):
        """Delete a user by ID"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM user_info WHERE id = ?", (user_id,))
            conn.commit()

    def update_user(self, user_id: int, name: str = None, email: str = None):
        """Update user information without alias"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM user_info WHERE id = ?", (user_id,))
            existing = cursor.fetchone()
            
            if not existing:
                raise ValueError(f"User with ID {user_id} not found")
            
            conn.execute("""
                UPDATE user_info 
                SET name = ?, email = ?
                WHERE id = ?
            """, (
                name if name else existing[1],
                email if email else existing[2],
                user_id
            ))
            conn.commit()

    def has_users(self):
        """Check if any users exist in the database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM user_info")
            count = cursor.fetchone()[0]
            return count > 0

    def authenticate(self):
        """Simplified authentication - always succeeds"""
        return True

    def get_connection(self):
        """Get a database connection"""
        return sqlite3.connect(self.db_path)

    def reset_sequence(self, table_name):
        """Reset the SQLite sequence counter for a table"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute(f"DELETE FROM sqlite_sequence WHERE name=?", (table_name,))
            conn.commit()
            cursor.close()
            conn.close()
        except Exception as e:
            logger.error(f"Error resetting sequence for {table_name}: {e}")
            raise

    def init_general_settings(self):
        """Initialize general settings in database"""
        settings = [
            # Rate Limiter Settings
            ('rate_limiter', 'requests_per_window', '10', 'int', 'Maximum requests per time window'),
            ('rate_limiter', 'window_seconds', '60', 'int', 'Time window in seconds'),
            
            # SMTP Settings
            ('smtp', 'timeout', '10', 'int', 'SMTP timeout in seconds'),
            ('smtp', 'max_retries', '3', 'int', 'Maximum retry attempts'),
            ('smtp', 'ports', '[25,587,465]', 'json', 'SMTP ports to try'),
            ('smtp', 'connection_pool_size', '10', 'int', 'Size of connection pool'),
            
            # Rate Limiting Settings
            ('rate_limits', 'smtp_connections', '{"requests":10,"window":60}', 'json', 'SMTP connection rate limits'),
            ('rate_limits', 'dns_lookups', '{"requests":100,"window":60}', 'json', 'DNS lookup rate limits'),
            ('rate_limits', 'email_validations', '{"requests":50,"window":60}', 'json', 'Email validation rate limits'),
        ]
        
        with self.conn:
            self.conn.executemany('''
                INSERT OR REPLACE INTO general_settings 
                (category, name, value, data_type, description)
                VALUES (?, ?, ?, ?, ?)
            ''', settings)

    def get_setting(self, category: str, name: str) -> Any:
        """Get a setting value with type conversion"""
        cursor = self.conn.execute('''
            SELECT value, data_type 
            FROM general_settings 
            WHERE category = ? AND name = ?
        ''', (category, name))
        
        row = cursor.fetchone()
        if row:
            value, data_type = row
            if data_type == 'int':
                return int(value)
            elif data_type == 'float':
                return float(value)
            elif data_type == 'json':
                return json.loads(value)
            return value
        return None

    def get_category_settings(self, category: str) -> Dict[str, Any]:
        """Get all settings for a category"""
        cursor = self.conn.execute('''
            SELECT name, value, data_type 
            FROM general_settings 
            WHERE category = ?
        ''', (category,))
        
        settings = {}
        for name, value, data_type in cursor.fetchall():
            if data_type == 'int':
                settings[name] = int(value)
            elif data_type == 'float':
                settings[name] = float(value)
            elif data_type == 'json':
                settings[name] = json.loads(value)
            else:
                settings[name] = value
        return settings

    def update_setting(self, category: str, name: str, value: Any):
        """Update a setting value"""
        # Convert value to string based on type
        if isinstance(value, (list, dict)):
            str_value = json.dumps(value)
            data_type = 'json'
        elif isinstance(value, int):
            str_value = str(value)
            data_type = 'int'
        elif isinstance(value, float):
            str_value = str(value)
            data_type = 'float'
        else:
            str_value = str(value)
            data_type = 'str'

        with self.conn:
            self.conn.execute('''
                UPDATE general_settings 
                SET value = ?, data_type = ?
                WHERE category = ? AND name = ?
            ''', (str_value, data_type, category, name))
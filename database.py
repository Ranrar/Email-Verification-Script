import sqlite3
import os
import getpass
from cryptography.fernet import Fernet
import sys
from datetime import datetime
import logging

# Configure logger
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

def clear_screen():
    """Clear the console screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

class Database:
    _instance = None
    
    def __new__(cls, config):
        if cls._instance is None:
            cls._instance = super(Database, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, config):
        if self._initialized:
            return
            
        self.db_dir = os.path.join(os.getcwd(), 'DB')
        self.db_path = os.path.join(self.db_dir, 'EVS.db')
        self.key_file = os.path.join(self.db_dir, 'db.key')
        self.config = config
        self.is_authenticated = False
        self.first_run = False
        self.current_user = None
        self.password = None
        
        # Create DB directory if it doesn't exist
        if not os.path.exists(self.db_dir):
            os.makedirs(self.db_dir)
            
        # Check if database exists
        if not os.path.exists(self.db_path):
            self.first_run = True
            self._initialize_new_database()
        else:
            # Don't load key here - wait for authenticate call
            self.is_authenticated = False
            
        self._initialized = True

    def _initialize_new_database(self):
        """Initialize a new database with user information first, then create with password"""
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
        
        alias = input("Alias (optional): ").strip() or None
        
        while True:
            email = input("Email: ").strip()
            if '@' in email and '.' in email:
                break
            print("Please enter a valid email address.")

        # Only after getting user info, create database with password
        if not os.path.exists(self.db_dir):
            os.makedirs(self.db_dir)

        print("\nCreate a password to protect your database:")
        while True:
            password = getpass.getpass("Database password: ")
            confirm = getpass.getpass("Confirm password: ")
            if password == confirm:
                break
            print("Passwords don't match. Please try again.")

        try:
            # Generate encryption key and create a key+password combination
            self.key = Fernet.generate_key()
            self.fernet = Fernet(self.key)
            
            # Store both key and encrypted password
            with open(self.key_file, 'wb') as f:
                encrypted_password = self.fernet.encrypt(password.encode())
                f.write(self.key + b":" + encrypted_password)

            # Initialize database structure
            self.password = password  # Store password for database encryption
            self.init_database()
            
            # Add initial user
            self.add_user(name, email, alias)
            print("\nDatabase and user profile created successfully!\n")
            
        except Exception as e:
            print(f"\nError creating database: {str(e)}")
            # Clean up if anything fails
            if os.path.exists(self.db_path):
                os.remove(self.db_path)
            if os.path.exists(self.key_file):
                os.remove(self.key_file)

    def _load_encryption_key(self):
        """Load existing encryption key with password verification"""
        clear_screen()
        print(""
"======================================================================\n"
    "Email Verification Script - Version 1.0\n"
    "Copyright (C) 2025 Kim Skov Rasmussen\n"
    "Licensed under GNU General Public License v3.0\n"  
    "This software is provided as is, without any warranties.\n"  
    "Use at your own risk. For educational purposes only.\n"
    "\n"
    "To get started, please login. Type 'help' to see all commands\n"
"======================================================================\n"
"")
    
        password = getpass.getpass("Password> ")
        
        try:
            # Read the stored key and encrypted password
            with open(self.key_file, 'rb') as f:
                stored_data = f.read()
            
            # Split the stored data into key and encrypted password
            key, encrypted_password = stored_data.split(b":")
            
            # Initialize Fernet with the stored key
            self.key = key
            self.fernet = Fernet(self.key)
            
            try:
                # Verify password
                decrypted_password = self.fernet.decrypt(encrypted_password)
                if decrypted_password.decode() != password:
                    raise ValueError("Invalid password")
                self.password = password  # Store password for database encryption
            except Exception:
                raise ValueError("Invalid password")
                    
        except Exception as e:
            print(f"Error accessing database: {str(e)}")
            sys.exit(1)

    def _check_auth(self):
        """Check if database is authenticated"""
        # Remove the _load_encryption_key call since authentication is handled elsewhere
        if not self.is_authenticated:
            raise ValueError("Database not authenticated")

    def encrypt(self, data):
        """Encrypt string data"""
        return self.fernet.encrypt(data.encode()).decode()

    def decrypt(self, data):
        """Decrypt string data"""
        return self.fernet.decrypt(data.encode()).decode()

    def init_database(self):
        """Initialize the database with full encryption"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(f"PRAGMA key='{self.password}'")  # Set database encryption key
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
                        check_count INTEGER DEFAULT 1
                    )
                """)
                
                # Create user_info table
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS user_info (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL,
                        alias TEXT,
                        email TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    )
                """)
                conn.commit()
        except Exception as e:
            raise Exception(f"Failed to initialize database: {str(e)}")

    def log_check(self, data):
        """Log an email check with encryption"""
        self._check_auth()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(f"PRAGMA key='{self.password}'")  # Set database encryption key
            cursor = conn.cursor()
            
            # Encrypt sensitive data
            encrypted_data = {
                'email': self.encrypt(data['email']),
                'domain': self.encrypt(data['domain']),
                'mx_record': self.encrypt(data.get('mx_record', '')),
                'smtp_banner': self.encrypt(data.get('smtp_banner', '')),
                'error_message': self.encrypt(data.get('error_message', '')),
                'imap_info': self.encrypt(data.get('imap_info', '')),
                'pop3_info': self.encrypt(data.get('pop3_info', ''))
            }
            
            # Check if email exists
            cursor.execute(
                "SELECT id, check_count FROM email_logs WHERE email = ?", 
                (encrypted_data['email'],)
            )
            existing = cursor.fetchone()

            if existing:
                # Update existing record
                conn.execute("""
                    UPDATE email_logs 
                    SET timestamp=?, mx_record=?, result=?, error_message=?,
                        disposable=?, spf_status=?, dkim_status=?, blacklist_info=?,
                        port=?, mx_ip=?, mx_preferences=?, smtp_banner=?,
                        smtp_vrfy=?, catch_all=?, imap_status=?, imap_info=?,
                        pop3_status=?, pop3_info=?, check_count=?
                    WHERE id=?
                """, (
                    data['timestamp'],
                    encrypted_data['mx_record'],
                    data.get('result', ''),
                    encrypted_data['error_message'],
                    data.get('disposable', ''),
                    data.get('spf_status', ''),
                    data.get('dkim_status', ''),
                    data.get('blacklist_info', ''),
                    data.get('port', ''),
                    data.get('mx_ip', ''),
                    data.get('mx_preferences', ''),
                    encrypted_data['smtp_banner'],
                    data.get('smtp_vrfy', ''),
                    data.get('catch_all', ''),
                    data.get('imap_status', ''),
                    encrypted_data['imap_info'],
                    data.get('pop3_status', ''),
                    encrypted_data['pop3_info'],
                    existing[1] + 1,
                    existing[0]
                ))
            else:
                # Insert new record
                conn.execute("""
                    INSERT INTO email_logs (
                        timestamp, email, domain, result, error_message,
                        disposable, spf_status, dkim_status, blacklist_info,
                        mx_record, port, mx_ip, mx_preferences, smtp_banner,
                        smtp_vrfy, catch_all, imap_status, imap_info,
                        pop3_status, pop3_info, check_count
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                """, (
                    data['timestamp'],
                    encrypted_data['email'],
                    encrypted_data['domain'],
                    data.get('result', ''),
                    encrypted_data['error_message'],
                    data.get('disposable', ''),
                    data.get('spf_status', ''),
                    data.get('dkim_status', ''),
                    data.get('blacklist_info', ''),
                    encrypted_data['mx_record'],
                    data.get('port', ''),
                    data.get('mx_ip', ''),
                    data.get('mx_preferences', ''),
                    encrypted_data['smtp_banner'],
                    data.get('smtp_vrfy', ''),
                    data.get('catch_all', ''),
                    data.get('imap_status', ''),
                    encrypted_data['imap_info'],
                    data.get('pop3_status', ''),
                    encrypted_data['pop3_info']
                ))
            conn.commit()

    def show_logs(self):
        """Retrieve and decrypt logs"""
        self._check_auth()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(f"PRAGMA key='{self.password}'")  # Set database encryption key
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM email_logs ORDER BY timestamp DESC")
            columns = [description[0] for description in cursor.description]
            rows = cursor.fetchall()
            
            # Decrypt sensitive data
            decrypted_rows = []
            for row in rows:
                decrypted_row = list(row)
                # Decrypt sensitive fields
                decrypted_row[2] = self.decrypt(row[2])    # email
                decrypted_row[3] = self.decrypt(row[3])    # domain
                decrypted_row[5] = self.decrypt(row[5])    # error_message
                decrypted_row[10] = self.decrypt(row[10])  # mx_record
                decrypted_row[14] = self.decrypt(row[14])  # smtp_banner
                decrypted_row[18] = self.decrypt(row[18])  # imap_info
                decrypted_row[20] = self.decrypt(row[20])  # pop3_info
                decrypted_rows.append(decrypted_row)
            
            return columns, decrypted_rows

    def clear_logs(self):
        """Clear all logs from the database"""
        self._check_auth()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(f"PRAGMA key='{self.password}'")  # Set database encryption key
            conn.execute("DELETE FROM email_logs")
            conn.commit()

    def clear_email_logs(self):
        """Clear all records from the email_logs table"""
        try:
            self._check_auth()  # Verify authentication
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(f"PRAGMA key='{self.password}'")  # Set database encryption key
                cursor = conn.cursor()
                cursor.execute("DELETE FROM email_logs")
                conn.commit()
        except Exception as e:
            logger.error(f"Error clearing email logs: {e}")
            raise

    def add_user(self, name: str, email: str, alias: str = None):
        """Add a new user with encrypted data"""
        self._check_auth()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(f"PRAGMA key='{self.password}'")  # Set database encryption key
            encrypted_data = {
                'name': self.encrypt(name),
                'email': self.encrypt(email),
                'alias': self.encrypt(alias) if alias else None
            }
            
            conn.execute("""
                INSERT INTO user_info (name, alias, email, created_at)
                VALUES (?, ?, ?, ?)
            """, (
                encrypted_data['name'],
                encrypted_data['alias'],
                encrypted_data['email'],
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ))
            conn.commit()

    def get_users(self):
        """Retrieve and decrypt user info"""
        self._check_auth()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(f"PRAGMA key='{self.password}'")  # Set database encryption key
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM user_info ORDER BY name")
            rows = cursor.fetchall()
            
            # Decrypt sensitive data
            decrypted_users = []
            for row in rows:
                decrypted_user = list(row)
                decrypted_user[1] = self.decrypt(row[1])  # name
                if row[2]:  # alias
                    decrypted_user[2] = self.decrypt(row[2])
                decrypted_user[3] = self.decrypt(row[3])  # email
                decrypted_users.append(decrypted_user)
            
            return decrypted_users

    def delete_user(self, user_id: int):
        """Delete a user by ID"""
        self._check_auth()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(f"PRAGMA key='{self.password}'")  # Set database encryption key
            conn.execute("DELETE FROM user_info WHERE id = ?", (user_id,))
            conn.commit()

    def update_user(self, user_id: int, name: str = None, email: str = None, alias: str = None):
        """Update user information"""
        self._check_auth()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(f"PRAGMA key='{self.password}'")  # Set database encryption key
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM user_info WHERE id = ?", (user_id,))
            existing = cursor.fetchone()
            
            if not existing:
                raise ValueError(f"User with ID {user_id} not found")
            
            encrypted_data = {
                'name': self.encrypt(name) if name else existing[1],
                'email': self.encrypt(email) if email else existing[3],
                'alias': self.encrypt(alias) if alias else existing[2]
            }
            
            conn.execute("""
                UPDATE user_info 
                SET name = ?, alias = ?, email = ?
                WHERE id = ?
            """, (
                encrypted_data['name'],
                encrypted_data['alias'],
                encrypted_data['email'],
                user_id
            ))
            conn.commit()

    def has_users(self):
        """Check if any users exist in the database"""
        self._check_auth()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(f"PRAGMA key='{self.password}'")  # Set database encryption key
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM user_info")
            count = cursor.fetchone()[0]
            return count > 0

    def _verify_password(self, password):
        """Verify if the provided password matches the database password"""
        try:
            with open(self.key_file, 'rb') as f:
                stored_data = f.read()
            key, encrypted_password = stored_data.split(b":")
            fernet = Fernet(key)
            decrypted_password = fernet.decrypt(encrypted_password)
            return decrypted_password.decode() == password
        except Exception:
            return False

    def authenticate(self, password):
        """Authenticate user and store username"""
        try:
            if self.is_authenticated:
                return True
                
            if not self._verify_password(password):
                return False
                
            # Load encryption key and store password
            with open(self.key_file, 'rb') as f:
                stored_data = f.read()
            key, _ = stored_data.split(b":")
            self.key = key
            self.fernet = Fernet(self.key)
            self.password = password
                
            # Get username from database
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(f"PRAGMA key='{self.password}'")
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM user_info WHERE id = 1")
                result = cursor.fetchone()
                
                if result:
                    self.current_user = self.decrypt(result[0])
                    self.is_authenticated = True
                    return True
            return False
                
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return False

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
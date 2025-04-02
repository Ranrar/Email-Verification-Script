import sqlite3
import os
import json
import inspect
from functools import lru_cache
from datetime import datetime
from packages.logger.logger import P_Log, DEFAULT_LOGGER_NAME

# Initialize logger early
logger = P_Log(log_to_console=False, split_by_level=True)

class ThreadPoolSettings:
    def __init__(self, config_instance):
        self._config = config_instance
        
    def __getattr__(self, name):
        conn = self._config.connect()
        if not conn:
            return None
            
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT value FROM thread_pool_settings WHERE setting_name = ?", 
                (name,)
            )
            result = cursor.fetchone()
            conn.close()
            
            if result:
                # Thread pool values are stored as integers
                return int(result['value'])
            return None
        except Exception as e:
            logger.warning(f"Error fetching thread_pool setting {name}: {e}")
            return None

class SmtpSettings:
    def __init__(self, config_instance):
        self._config = config_instance
        
    def __getattr__(self, name):
        conn = self._config.connect()
        if not conn:
            return None
            
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT value, data_type FROM smtp_settings WHERE setting_name = ?", 
                (name,)
            )
            result = cursor.fetchone()
            conn.close()
            
            if result:
                value, data_type = result['value'], result['data_type']
                if data_type == 'integer':
                    return int(value)
                elif data_type == 'float':
                    return float(value) 
                elif data_type == 'boolean':
                    return value.lower() == 'true'
                return value
            return None
        except Exception as e:
            logger.warning(f"Error fetching smtp setting {name}: {e}")
            return None

class ImapSettings:
    def __init__(self, config_instance):
        self._config = config_instance
        
    def __getattr__(self, name):
        conn = self._config.connect()
        if not conn:
            return None
            
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT value, data_type FROM imap_settings WHERE setting_name = ?", 
                (name,)
            )
            result = cursor.fetchone()
            conn.close()
            
            if result:
                value, data_type = result['value'], result['data_type']
                if data_type == 'integer':
                    return int(value)
                elif data_type == 'float':
                    return float(value)
                elif data_type == 'boolean':
                    return value.lower() == 'true'
                return value
            return None
        except Exception as e:
            logger.warning(f"Error fetching imap setting {name}: {e}")
            return None

class Pop3Settings:
    def __init__(self, config_instance):
        self._config = config_instance
        
    def __getattr__(self, name):
        conn = self._config.connect()
        if not conn:
            return None
            
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT value, data_type FROM pop3_settings WHERE setting_name = ?", 
                (name,)
            )
            result = cursor.fetchone()
            conn.close()
            
            if result:
                value, data_type = result['value'], result['data_type']
                if data_type == 'integer':
                    return int(value)
                elif data_type == 'float':
                    return float(value)
                elif data_type == 'boolean':
                    return value.lower() == 'true'
                return value
            return None
        except Exception as e:
            logger.warning(f"Error fetching pop3 setting {name}: {e}")
            return None

class DnsSettings:
    def __init__(self, config_instance):
        self._config = config_instance
        
    def __getattr__(self, name):
        conn = self._config.connect()
        if not conn:
            return None
            
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT value, data_type FROM dns_settings WHERE setting_name = ?", 
                (name,)
            )
            result = cursor.fetchone()
            conn.close()
            
            if result:
                value, data_type = result['value'], result['data_type']
                if data_type == 'integer':
                    return int(value)
                elif data_type == 'float':
                    return float(value)
                elif data_type == 'boolean':
                    return value.lower() == 'true'
                return value
            return None
        except Exception as e:
            logger.warning(f"Error fetching dns setting {name}: {e}")
            return None

class RateLimits:
    def __init__(self, config_instance):
        self._config = config_instance
        self._default_max_requests = None
        self._default_time_window = None
        self._load_defaults()
    
    def _load_defaults(self):
        """Load default rate limit values"""
        conn = self._config.connect()
        if not conn:
            return
            
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT max_requests, time_window FROM rate_limits WHERE operation = 'default'"
            )
            result = cursor.fetchone()
            conn.close()
            
            if result:
                self._default_max_requests = int(result['max_requests'])
                self._default_time_window = int(result['time_window'])
                logger.info(f"Loading rate limits: {self._default_max_requests} requests per {self._default_time_window}s")
        except Exception as e:
            logger.warning(f"Error loading default rate limits: {e}")
    
    @property
    def max_requests(self):
        """Get default max_requests value"""
        return self._default_max_requests
    
    @property
    def time_window(self):
        """Get default time_window value"""
        return self._default_time_window
        
    def __getattr__(self, name):
        """Get operation-specific rate limits"""
        conn = self._config.connect()
        if not conn:
            return None
            
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT max_requests, time_window FROM rate_limits WHERE operation = ?", 
                (name,)
            )
            result = cursor.fetchone()
            conn.close()
            
            if result:
                return {
                    'max_requests': int(result['max_requests']),
                    'time_window': int(result['time_window'])
                }
            return None
        except Exception as e:
            logger.warning(f"Error fetching rate limit {name}: {e}")
            return None

class CacheSettings:
    def __init__(self, config_instance):
        self._config = config_instance
        
    def __getattr__(self, name):
        conn = self._config.connect()
        if not conn:
            return None
            
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT max_size, ttl_seconds, cleanup_interval FROM cache_settings WHERE cache_name = ?", 
                (name,)
            )
            result = cursor.fetchone()
            conn.close()
            
            if result:
                return {
                    'max_size': int(result['max_size']),
                    'ttl_seconds': int(result['ttl_seconds']),
                    'cleanup_interval': int(result['cleanup_interval'])
                }
            return None
        except Exception as e:
            logger.warning(f"Error fetching cache setting {name}: {e}")
            return None

class ValidationScoring:
    def __init__(self, config_instance):
        self._config = config_instance
        self._scores = {}
        self._load_scores()
    
    def _load_scores(self):
        """Load scoring values from database"""
        try:
            with sqlite3.connect(self._config.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("SELECT check_name, score_value, is_penalty FROM validation_scoring")
                rows = cursor.fetchall()
                
                for row in rows:
                    value = row['score_value']
                    if row['is_penalty'] == 1:
                        value = -value
                    self._scores[row['check_name']] = value
        except Exception as e:
            logger.error(f"Error loading validation scores: {e}")
    
    def get_score(self, check_name, default=0):
        """Get score value for a specific check"""
        return self._scores.get(check_name, default)

    def __getattr__(self, name):
        """Allow attribute-style access to scores"""
        return self.get_score(name)

class SmtpPorts:
    def __init__(self, config_instance):
        self._config = config_instance
    
    def get_all(self, enabled_only=True):
        """Get all SMTP ports ordered by priority"""
        conn = self._config.connect()
        if not conn:
            return []
            
        try:
            cursor = conn.cursor()
            if enabled_only:
                cursor.execute(
                    "SELECT port, priority FROM smtp_ports WHERE enabled = 1 ORDER BY priority ASC"
                )
            else:
                cursor.execute(
                    "SELECT port, priority, enabled FROM smtp_ports ORDER BY priority ASC"
                )
            
            result = cursor.fetchall()
            conn.close()
            
            return [int(row['port']) for row in result]  # Returns a list of integers
        except Exception as e:
            logger.warning(f"Error fetching SMTP ports: {e}")
            return []

class AppSettings:
    def __init__(self, config_instance):
        self._config = config_instance
        
    def get(self, category, name=None, default=None):
        """
        Get a configuration setting by category and name.
        If only category is provided, return all settings for that category.
        Returns the default value if the setting is not found.
        """
        try:
            # Use the parent config's database path
            with sqlite3.connect(self._config.db_path) as conn:
                cursor = conn.cursor()
                
                if name is None:
                    # If only category is provided, return all settings for that category
                    cursor.execute(
                        "SELECT name, value, data_type FROM app_settings WHERE category = ?",
                        (category,)
                    )
                    results = cursor.fetchall()
                    
                    if results:
                        settings = {}
                        for row in results:
                            if isinstance(row, sqlite3.Row):
                                setting_name = row['name']
                                value = row['value']
                                data_type = row['data_type']
                            else:
                                setting_name, value, data_type = row
                            
                            # Convert the value based on data type
                            if data_type == 'integer':
                                settings[setting_name] = int(value)
                            elif data_type == 'float':
                                settings[setting_name] = float(value)
                            elif data_type == 'boolean':
                                settings[setting_name] = value.lower() == 'true'
                            elif data_type == 'json':
                                settings[setting_name] = json.loads(value)
                            else:
                                settings[setting_name] = value
                        
                        return settings
                    return default
                else:
                    # If both category and name are provided, return the specific setting
                    cursor.execute(
                        "SELECT value, data_type FROM app_settings WHERE category = ? AND name = ?",
                        (category, name)
                    )
                    result = cursor.fetchone()
                    
                    if result:
                        if isinstance(result, sqlite3.Row):
                            value, data_type = result['value'], result['data_type']
                        else:
                            value, data_type = result
                            
                        # Convert the value based on data type
                        if data_type == 'integer':
                            return int(value)
                        elif data_type == 'float':
                            return float(value)
                        elif data_type == 'boolean':
                            return value.lower() == 'true'
                        elif data_type == 'json':
                            return json.loads(value)
                        return value
                    return default
        except Exception as e:
            logger.error(f"Error getting config value for {category}.{name if name else ''}: {e}")
            return default

class ConfidenceLevels:
    def __init__(self, config_instance):
        self._config = config_instance
    
    def get_level_for_score(self, score):
        """Get the confidence level name for a given score"""
        conn = self._config.connect()
        if not conn:
            return None
            
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT level_name FROM confidence_levels WHERE ? BETWEEN min_threshold AND max_threshold", 
                (score,)
            )
            result = cursor.fetchone()
            conn.close()
            
            if result:
                return result['level_name']
            return None
        except Exception as e:
            logger.warning(f"Error getting confidence level for score {score}: {e}")
            return None
    
    def get_all(self):
        """Get all confidence levels"""
        conn = self._config.connect()
        if not conn:
            return {}
            
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT level_name, min_threshold, max_threshold, description FROM confidence_levels ORDER BY min_threshold ASC"
            )
            result = cursor.fetchall()
            conn.close()
            
            levels = {}
            for row in result:
                levels[row['level_name']] = {
                    'min': int(row['min_threshold']),
                    'max': int(row['max_threshold']),
                    'description': row['description']
                }
            return levels
        except Exception as e:
            logger.warning(f"Error fetching confidence levels: {e}")
            return {}

class DisposableDomains:
    def __init__(self, config_instance):
        self._config = config_instance
    
    def is_disposable(self, domain):
        """Check if a domain is in the disposable domains list"""
        conn = self._config.connect()
        if not conn:
            return False
            
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT 1 FROM disposable_domains WHERE domain = ?", 
                (domain.lower(),)
            )
            result = cursor.fetchone()
            conn.close()
            
            return result is not None
        except Exception as e:
            logger.warning(f"Error checking if {domain} is disposable: {e}")
            return False

class BlacklistedDomains:
    def __init__(self, config_instance):
        self._config = config_instance
    
    def is_blacklisted(self, domain):
        """Check if a domain is blacklisted and return sources"""
        conn = self._config.connect()
        if not conn:
            return False, []
            
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT source FROM blacklisted_domains WHERE domain = ?", 
                (domain.lower(),)
            )
            results = cursor.fetchall()
            conn.close()
            
            if results:
                sources = [row['source'] for row in results]
                return True, sources
            return False, []
        except Exception as e:
            logger.warning(f"Error checking if {domain} is blacklisted: {e}")
            return False, []

class EmailRecordFields:
    def __init__(self, config_instance):
        self._config = config_instance
    
    def get_all(self):
        """Get all field definitions"""
        conn = self._config.connect()
        if not conn:
            return {}
            
        try:
            cursor = conn.cursor()
            cursor.execute(
                """SELECT name, display_name, category, display_index, visible, description 
                   FROM email_records_field_definitions 
                   ORDER BY display_index ASC"""
            )
            results = cursor.fetchall()
            conn.close()
            
            fields = {}
            for row in results:
                fields[row['name']] = {
                    'display': row['display_name'],
                    'category': row['category'],
                    'index': row['display_index'],
                    'visible': row['visible'] == 'Y',
                    'description': row['description']
                }
            return fields
        except Exception as e:
            logger.warning(f"Error fetching email record fields: {e}")
            return {}

class BatchInfo:
    def __init__(self, config_instance):
        self._config = config_instance
    
    def create_batch(self, name=None, source=None, total_emails=0, settings_snapshot=None):
        """Create a new batch and return its ID"""
        conn = self._config.connect()
        if not conn:
            return None
            
        try:
            cursor = conn.cursor()
            now = datetime.now().isoformat()
            
            # Convert settings_snapshot to JSON string if provided
            settings_json = None
            if settings_snapshot:
                settings_json = json.dumps(settings_snapshot)
            
            cursor.execute(
                """INSERT INTO batch_info 
                   (name, source, created_at, total_emails, status, settings_snapshot) 
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (name, source, now, total_emails, 'queued', settings_json)
            )
            conn.commit()
            batch_id = cursor.lastrowid
            conn.close()
            
            logger.info(f"Created new batch {batch_id}: {name} with {total_emails} emails")
            return batch_id
        except Exception as e:
            logger.error(f"Error creating batch: {e}")
            return None
    
    def update_batch_status(self, batch_id, status, processed=None, success=None, 
                           failed=None, error_message=None, completed=False):
        """Update the status and stats of a batch"""
        conn = self._config.connect()
        if not conn:
            return False
            
        try:
            cursor = conn.cursor()
            
            # Build the query dynamically based on provided arguments
            update_fields = ["status = ?"]
            params = [status]
            
            if processed is not None:
                update_fields.append("processed_emails = ?")
                params.append(processed)
                
            if success is not None:
                update_fields.append("success_count = ?")
                params.append(success)
                
            if failed is not None:
                update_fields.append("failed_count = ?")
                params.append(failed)
                
            if error_message is not None:
                update_fields.append("error_message = ?")
                params.append(error_message)
                
            if completed:
                update_fields.append("completed_at = ?")
                params.append(datetime.now().isoformat())
            
            # Construct the final query
            query = f"UPDATE batch_info SET {', '.join(update_fields)} WHERE id = ?"
            params.append(batch_id)
            
            cursor.execute(query, params)
            conn.commit()
            conn.close()
            
            logger.debug(f"Updated batch {batch_id} status to {status}")
            return True
        except Exception as e:
            logger.error(f"Error updating batch {batch_id}: {e}")
            return False
    
    def get_batch(self, batch_id):
        """Get batch details by ID"""
        conn = self._config.connect()
        if not conn:
            return None
            
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM batch_info WHERE id = ?", (batch_id,))
            result = cursor.fetchone()
            conn.close()
            
            if not result:
                return None
                
            # Convert to dictionary
            batch = dict(result)
            
            # Parse settings_snapshot if it exists
            if batch.get('settings_snapshot'):
                try:
                    batch['settings_snapshot'] = json.loads(batch['settings_snapshot'])
                except json.JSONDecodeError as e:
                    # Log the error but keep the original string value
                    logger.debug(f"Could not parse settings_snapshot as JSON for batch {batch.get('id', 'unknown')}: {e}")
                    pass
                    
            return batch
        except Exception as e:
            logger.error(f"Error fetching batch {batch_id}: {e}")
            return None
    
    def list_batches(self, limit=100, status=None, order_by="created_at DESC"):
        """List batches with optional filtering"""
        conn = self._config.connect()
        if not conn:
            return []
            
        try:
            cursor = conn.cursor()
            
            query = "SELECT id, name, source, created_at, completed_at, total_emails, " \
                    "processed_emails, success_count, failed_count, status " \
                    "FROM batch_info"
                    
            params = []
            
            # Add status filter if provided
            if status:
                query += " WHERE status = ?"
                params.append(status)
                
            # Add ordering
            query += f" ORDER BY {order_by} LIMIT ?"
            params.append(limit)
            
            cursor.execute(query, params)
            results = cursor.fetchall()
            conn.close()
            
            # Convert to list of dictionaries
            batches = [dict(row) for row in results]
            return batches
        except Exception as e:
            logger.error(f"Error listing batches: {e}")
            return []

class config:
    """Direct access to configuration variables stored in the EVS.db database"""
    
    _instance = None
    
    def __new__(cls, db_path=None):
        """Singleton pattern to ensure only one config instance exists"""
        if cls._instance is None:
            cls._instance = super(config, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self, db_path=None):
        """Initialize with optional custom database path"""
        if self._initialized:
            return
            
        # Default database path if not provided
        if not db_path:
            self.db_dir = os.path.join(os.getcwd(), 'DB')
            self.db_path = os.path.join(self.db_dir, 'EVS.db')
        else:
            self.db_path = db_path
        
        # Add a flag to track database state
        self._db_available = self.db_exists()
        
        # If database doesn't exist, log once instead of on every access
        if not self._db_available:
            logger.warning("Database does not exist or is empty.")
    
        # Initialize settings accessors
        self.thread_pool_setting = ThreadPoolSettings(self)
        self.smtp_setting = SmtpSettings(self)
        self.smtp_ports = SmtpPorts(self)
        self.imap_setting = ImapSettings(self)
        self.pop3_setting = Pop3Settings(self)
        self.dns_setting = DnsSettings(self)
        self.rate_limit = RateLimits(self)
        self.cache_setting = CacheSettings(self)
        self.app_setting = AppSettings(self)
        self.validation_scoring = ValidationScoring(self)
        self.confidence_level = ConfidenceLevels(self)
        self.disposable_domain = DisposableDomains(self)
        self.blacklisted_domain = BlacklistedDomains(self)
        self.email_record_field = EmailRecordFields(self)
        self.batch_info = BatchInfo(self)  # Add the new BatchInfo class
        
        self._initialized = True
        
        # logger.info(f"Config initialized with database path {self.db_path}")
    
    def db_exists(self):
        """Check if database file exists and has content"""
        return os.path.exists(self.db_path) and os.path.getsize(self.db_path) > 0
    
    def connect(self):
        """Create a database connection only if DB exists"""
        # Check if database exists first
        if not self._db_available and not self.db_exists():
            return None
            
        # If we reach here, database might have been created since initialization
        if not self._db_available:
            self._db_available = True
        
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row  # Enable column access by name
            return conn
        except sqlite3.Error as e:
            logger.error(f"Database connection error: {e}")
            return None
    
    def refresh(self):
        """Refresh any internal caches"""
        pass

    def get_active_user(self):
        """Get the currently active user"""
        caller = inspect.currentframe().f_back.f_code.co_name
        logger.info(f"get_active_user method called from {caller}")
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id, name, email, created_at FROM users WHERE is_active = 1 LIMIT 1")
                user = cursor.fetchone()
                if user:
                    return {"id": user[0], "name": user[1], "email": user[2], "created_at": user[3]}
                return None
        except Exception as e:
            logger.error(f"Error getting active user: {e}")
            return None

    def refresh_db_state(self):
        """Refreshes database state and clears cached values"""
        try:
            
            # Re-initialize settings accessors to reset their state
            self._db_available = self.db_exists()
            
            # Re-initialize all settings accessors to force them to reload data
            self.thread_pool_setting = ThreadPoolSettings(self)
            self.smtp_setting = SmtpSettings(self)
            self.smtp_ports = SmtpPorts(self)
            self.imap_setting = ImapSettings(self)
            self.pop3_setting = Pop3Settings(self)
            self.dns_setting = DnsSettings(self)
            self.rate_limit = RateLimits(self)
            self.cache_setting = CacheSettings(self)
            self.app_setting = AppSettings(self)
            self.validation_scoring = ValidationScoring(self)
            self.confidence_level = ConfidenceLevels(self)
            self.disposable_domain = DisposableDomains(self)
            self.blacklisted_domain = BlacklistedDomains(self)
            self.email_record_field = EmailRecordFields(self)
            self.batch_info = BatchInfo(self)  # Reinitialize batch info
            
            # Explicitly reload validation scores
            self.validation_scoring._load_scores()
            
            logger.info("Database clearing caches")
            return True
        except Exception as e:
            logger.error(f"Failed to refresh database state: {e}")
            return False
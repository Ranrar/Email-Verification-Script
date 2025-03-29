import os
import logging
import warnings
import weakref
import json
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler

# Define default logger name as ISO date format
DEFAULT_LOGGER_NAME = datetime.now().strftime('%Y%m%d')  # Generates '20250322' format

# Silence warnings (optional)
warnings.filterwarnings('ignore')

# Silence other Python loggers that might be printing to console
for log_name in ['urllib3', 'chardet', 'dns', 'imaplib', 'poplib']:
    logging.getLogger(log_name).setLevel(logging.INFO)
    logging.getLogger(log_name).propagate = False

# Create a custom JSON formatter
class JsonFormatter(logging.Formatter):
    """Format log records as JSON strings"""
    def format(self, record):
        log_data = {
            "timestamp": self.formatTime(record, self.datefmt),
            "module": record.module,
            "function": record.funcName,
            "level": record.levelname,
            "message": record.getMessage()
        }
        
        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        return json.dumps(log_data)

# Create a human-readable text formatter for console output
class TextFormatter(logging.Formatter):
    """Format log records as human-readable text"""
    def format(self, record):
        timestamp = self.formatTime(record, self.datefmt)
        module = record.module
        function = record.funcName
        level = record.levelname
        message = record.getMessage()
        
        # Format as "timestamp - module.function - LEVEL: message"
        result = f"{timestamp} - {module}.{function} - {level}: {message}"
        
        # Add exception info if present
        if record.exc_info:
            result += f"\n    EXCEPTION: {self.formatException(record.exc_info)}"
        
        return result

# Store logger instances in a weak reference dictionary
_logger_instances = weakref.WeakValueDictionary()

def P_Log(logger_name=DEFAULT_LOGGER_NAME, log_level=logging.DEBUG, log_to_console=False, 
          backup_count=30):  # Reduced from 300 to 30 days
    """Configure application logging with file logging and optional console output"""
    # Check if logger already exists with same name to avoid duplicates
    if logger_name in _logger_instances:
        return _logger_instances[logger_name]
    
    # Ensure logs directory exists
    logs_dir = os.path.join(os.getcwd(), 'logs')
    if not os.path.exists(logs_dir):
        os.makedirs(logs_dir)
    
    # Use a consistent base filename without date - TimedRotatingFileHandler will add dates
    base_log_file = os.path.join(logs_dir, f'{logger_name}.log')
    
    logger = logging.getLogger(logger_name)
    logger.setLevel(log_level)
    
    # Clear any existing handlers to avoid duplicates
    if logger.handlers:
        logger.handlers = []
    
    # Use TimedRotatingFileHandler with the base filename
    file_handler = TimedRotatingFileHandler(
        base_log_file,
        when='midnight',
        interval=1,
        backupCount=backup_count
    )
    # Set custom suffix to include date in rotated files
    file_handler.suffix = "%Y-%m-%d.log"
    file_handler.setLevel(log_level)
    
    # Use JSON formatter for file logs
    file_formatter = JsonFormatter(datefmt="%Y-%m-%d %H:%M:%S")
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    if log_to_console:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        # Use text formatter for console output
        console_formatter = TextFormatter(datefmt="%Y-%m-%d %H:%M:%S")
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
    
    logger.propagate = False
    
    # Run garbage collection after setup to clean any leaked file handles
    import gc
    gc.collect()
    
    # Store in weak reference dictionary
    _logger_instances[logger_name] = logger
    
    return logger

def close_logger(logger):
    """Properly close all handlers attached to the logger"""
    if logger:
        for handler in logger.handlers[:]:
            handler.close()
            logger.removeHandler(handler)

class LoggerManager:
    """Context manager for logger to ensure proper cleanup"""
    def __init__(self, logger_name=DEFAULT_LOGGER_NAME, log_level=logging.DEBUG, log_to_console=False, backup_count=30):
        self.logger = P_Log(logger_name, log_level, log_to_console, backup_count)
        
    def __enter__(self):
        return self.logger
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        close_logger(self.logger)
        
    @staticmethod
    def cleanup_old_logs(logs_dir=None, max_days=30):
        """Remove log files older than max_days from main logs directory and archive them"""
        import time
        import shutil
        
        if logs_dir is None:
            logs_dir = os.path.join(os.getcwd(), 'logs')
            
        if not os.path.exists(logs_dir):
            return
        
        # Create the backup directory if it doesn't exist
        backup_dir = os.path.join(os.getcwd(), 'logs_archive')
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)
            
        current_time = time.time()
        max_age = max_days * 86400  # Convert days to seconds
        
        for filename in os.listdir(logs_dir):
            file_path = os.path.join(logs_dir, filename)
            if os.path.isfile(file_path) and filename.endswith('.log'):
                file_age = current_time - os.path.getmtime(file_path)
                
                # If file is older than max_days, move it to backup directory
                if file_age > max_age:
                    backup_path = os.path.join(backup_dir, filename)
                    try:
                        # If file already exists in backup, add timestamp to make name unique
                        if os.path.exists(backup_path):
                            backup_name = f"{os.path.splitext(filename)[0]}_{int(current_time)}.log"
                            backup_path = os.path.join(backup_dir, backup_name)
                        
                        # Move the file to backup location
                        shutil.move(file_path, backup_path)
                    except Exception as e:
                        # Fallback to just deleting the file if move fails
                        try:
                            os.remove(file_path)
                        except Exception:
                            pass

    @staticmethod
    def organize_log_archive(archive_dir=None, organize_by='month'):
        """
        Organize archived logs by year/month folders.
        
        Structure:
        logs_archive/
            2025/
                01 - January/
                    20250101.log
                    20250102.log
                02 - February/
                    20250201.log
                ...
            2024/
                12 - December/
                    20241225.log
        """
        import re
        import time
        import shutil
        from datetime import datetime
        
        # Month names mapping
        month_names = {
            1: "January", 2: "February", 3: "March", 4: "April",
            5: "May", 6: "June", 7: "July", 8: "August",
            9: "September", 10: "October", 11: "November", 12: "December"
        }
        
        if archive_dir is None:
            archive_dir = os.path.join(os.getcwd(), 'logs_archive')
        
        if not os.path.exists(archive_dir):
            return False  # Nothing to organize
        
        # Scan all log files
        for filename in os.listdir(archive_dir):
            file_path = os.path.join(archive_dir, filename)
            
            # Skip directories and non-log files
            if not os.path.isfile(file_path) or not filename.endswith('.log'):
                continue
                
            # Try to extract date from filename patterns
            date_match = None
            
            # Try YYYYMMDD pattern (common in your logs)
            pattern1 = re.compile(r'^(\d{4})(\d{2})(\d{2})\.log')
            match = pattern1.match(filename)
            if match:
                year, month, day = match.groups()
                date_match = (year, month, day)
            
            # Try YYYY-MM-DD pattern (common in rotated logs)
            if not date_match:
                pattern2 = re.compile(r'.*\.(\d{4})-(\d{2})-(\d{2})$')
                match = pattern2.match(filename)
                if match:
                    year, month, day = match.groups()
                    date_match = (year, month, day)
            
            # If no pattern matches, use file modification time
            if not date_match:
                file_time = os.path.getmtime(file_path)
                time_struct = time.localtime(file_time)
                year = str(time_struct.tm_year)
                month = f"{time_struct.tm_mon:02d}"
                day = f"{time_struct.tm_mday:02d}"
                date_match = (year, month, day)
                
            year, month, day = date_match
            month_num = int(month)
            
            # Create year directory if it doesn't exist
            year_dir = os.path.join(archive_dir, year)
            if not os.path.exists(year_dir):
                os.makedirs(year_dir)
                
            # Create month directory with name if it doesn't exist
            month_dir_name = f"{month} - {month_names[month_num]}"
            month_dir = os.path.join(year_dir, month_dir_name)
            if not os.path.exists(month_dir):
                os.makedirs(month_dir)
                
            # Move the log file to the appropriate directory
            dest_path = os.path.join(month_dir, filename)
            if os.path.exists(dest_path):
                # If file already exists, add timestamp to make name unique
                base, ext = os.path.splitext(filename)
                dest_path = os.path.join(month_dir, f"{base}_{int(time.time())}{ext}")
                
            try:
                shutil.move(file_path, dest_path)
            except Exception as e:
                print(f"Error moving {file_path} to {dest_path}: {e}")
                
        return True
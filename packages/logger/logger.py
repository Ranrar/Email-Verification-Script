import os
import logging
import warnings
import weakref
import json
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler
import shutil
import time

# Define default logger name as ISO date format
DEFAULT_LOGGER_NAME = datetime.now().strftime('%Y%m%d')  # Generates '20250322' format

# Silence warnings (optional)
warnings.filterwarnings('ignore')

# Silence other Python loggers that might be printing to console
for log_name in ['urllib3', 'chardet', 'dns', 'imaplib', 'poplib']:
    logging.getLogger(log_name).setLevel(logging.CRITICAL)
    logging.getLogger(log_name).propagate = False

# Ensure logs directory exists
LOGS_DIR = os.path.join(os.getcwd(), 'logs')

# Create a dedicated error logger
def setup_error_logger():
    """Set up a dedicated logger for error tracking."""
    error_logger = logging.getLogger("error_logger")
    error_logger.setLevel(logging.ERROR)

    # Create a file handler for error logs
    error_log_file = os.path.join(LOGS_DIR, 'errors.log')
    
    class LazyFileHandler(logging.FileHandler):
        def __init__(self, filename, mode='a', encoding=None, delay=True):
            super().__init__(filename, mode, encoding, delay=True)
            
        def emit(self, record):
            if not os.path.exists(os.path.dirname(self.baseFilename)):
                os.makedirs(os.path.dirname(self.baseFilename), exist_ok=True)
            return super().emit(record)
    
    file_handler = LazyFileHandler(error_log_file, delay=True)
    file_handler.setLevel(logging.ERROR)

    # Use a simple formatter for error logs
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)

    # Add the handler to the logger
    error_logger.addHandler(file_handler)
    return error_logger

# Initialize the error logger
error_logger = setup_error_logger()

# Create a custom JSON formatter
class JsonFormatter(logging.Formatter):
    """Format log records as JSON strings"""
    def format(self, record):
        # Get module and function names
        module_name = record.module if hasattr(record, 'module') else 'unknown'
        function_name = record.funcName if hasattr(record, 'funcName') else 'unknown'
        
        # For module-level code, provide better context
        if function_name == '<module>':
            # If running at module level, include filename for better context
            filename = getattr(record, 'filename', 'unknown')
            lineno = getattr(record, 'lineno', 0)
            function_name = f"Module@Line{lineno}"
        
        log_data = {
            "timestamp": self.formatTime(record, self.datefmt),
            "module": module_name,
            "function": function_name,
            "level": record.levelname,
            "message": record.getMessage()
        }
        
        # Add file information for better tracking
        log_data["file"] = getattr(record, 'pathname', 'unknown')
        log_data["line"] = getattr(record, 'lineno', 0)
        
        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        return json.dumps(log_data)

# Store logger instances in a weak reference dictionary
_logger_instances = weakref.WeakValueDictionary()

class LazyTimedRotatingFileHandler(TimedRotatingFileHandler):
    """A file handler that creates the log file only when it's actually needed"""
    
    def __init__(self, filename, when='h', interval=1, backupCount=0, encoding=None, 
                 delay=True, utc=False, atTime=None):
        # Force delay=True to ensure the file isn't created until needed
        super().__init__(filename, when, interval, backupCount, encoding, 
                         delay=True, utc=utc, atTime=atTime)
    
    def emit(self, record):
        """Create containing directory only when emitting first record"""
        if not os.path.exists(os.path.dirname(self.baseFilename)):
            os.makedirs(os.path.dirname(self.baseFilename), exist_ok=True)
        return super().emit(record)


def P_Log(logger_name=DEFAULT_LOGGER_NAME, log_level=logging.DEBUG, log_to_console=False, 
          backup_count=30, split_by_level=False):
    """Configure application logging with file logging and optional console output"""
    # Check if logger already exists with same name to avoid duplicates
    if logger_name in _logger_instances:
        return _logger_instances[logger_name]
    
    # Ensure logs directory exists - DON'T create it yet, let handlers do that when needed
    logs_dir = os.path.join(os.getcwd(), 'logs')
    
    # Base log file path without level distinction
    base_log_file = os.path.join(logs_dir, f'{logger_name}.log')
    
    logger = logging.getLogger(logger_name)
    logger.setLevel(log_level)
    
    # Clear any existing handlers to avoid duplicates
    if logger.handlers:
        logger.handlers = []
    
    if split_by_level:
        # Create separate handlers for each log level
        log_levels = [
            (logging.DEBUG, "debug"),
            (logging.INFO, "info"),
            (logging.WARNING, "warning"),
            (logging.ERROR, "error"),
            (logging.CRITICAL, "critical")
        ]
        
        # Get the current date in YYYYMMDD format
        current_date = datetime.now().strftime('%Y%m%d')
        
        for level, level_name in log_levels:
            # Skip levels below the configured log_level
            if level < log_level:
                continue
                
            # Create level-specific log file with level name first, then date
            level_log_file = os.path.join(logs_dir, f'{level_name}.{current_date}.log')
            
            # Create a handler for this specific level - use LazyTimedRotatingFileHandler
            file_handler = LazyTimedRotatingFileHandler(
                level_log_file,
                when='midnight',
                interval=1,
                backupCount=backup_count,
                delay=True  # Important: delay file creation until first log
            )
            # Update the suffix to maintain naming consistency when rotated
            file_handler.suffix = "-%Y%m%d"
            
            # Filter to include only this specific level
            class LevelFilter(logging.Filter):
                def __init__(self, level):
                    self.level = level
                    
                def filter(self, record):
                    return record.levelno == self.level
            
            file_handler.addFilter(LevelFilter(level))
            file_handler.setLevel(level)
            
            # Use JSON formatter for file logs
            file_formatter = JsonFormatter(datefmt="%Y-%m-%d %H:%M:%S")
            file_handler.setFormatter(file_formatter)
            logger.addHandler(file_handler)
    else:
        # Original behavior: single log file for all levels - use LazyTimedRotatingFileHandler
        file_handler = LazyTimedRotatingFileHandler(
            base_log_file,
            when='midnight',
            interval=1,
            backupCount=backup_count,
            delay=True  # Important: delay file creation until first log
        )
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
        console_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s', datefmt="%Y-%m-%d %H:%M:%S")
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
    
    logger.propagate = False
    
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
    def __init__(self, logger_name=DEFAULT_LOGGER_NAME, log_level=logging.DEBUG, log_to_console=False, backup_count=30, split_by_level=False):
        self.logger = P_Log(logger_name, log_level, log_to_console, backup_count, split_by_level)
        
    def __enter__(self):
        return self.logger
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        close_logger(self.logger)
        
    @staticmethod
    def cleanup_old_logs(logs_dir=None, max_days=30):
        """Remove log files older than max_days from main logs directory and archive them"""
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
                        # Log the error instead of passing silently
                        error_logger.error(f"Failed to move {file_path} to {backup_path}: {e}")
                        try:
                            os.remove(file_path)
                        except Exception as delete_error:
                            error_logger.error(f"Failed to delete {file_path}: {delete_error}")

    @staticmethod
    def organize_log_archive(archive_dir=None, organize_by='month'):
        """
        Organize archived logs by year/month folders.
        """
        import re
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
                error_logger.error(f"Error moving {file_path} to {dest_path}: {e}")
                
        return True
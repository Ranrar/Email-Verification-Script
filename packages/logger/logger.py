import os
import logging
import warnings
from datetime import datetime
from logging.handlers import RotatingFileHandler

# Silence warnings (optional)
warnings.filterwarnings('ignore')

# Silence other Python loggers that might be printing to console
for log_name in ['urllib3', 'chardet', 'dns', 'imaplib', 'poplib']:
    logging.getLogger(log_name).setLevel(logging.CRITICAL)
    logging.getLogger(log_name).propagate = False

def P_Log(logger_name='evs', log_level=logging.DEBUG, log_to_console=False, 
          max_bytes=10*1024*1024, backup_count=5):  # Default 10MB file size, keep 5 backups
    """Configure application logging with file logging and optional console output
    
    Args:
        logger_name (str): Name of the logger and log file (default: 'evs')
        log_level (int): The minimum logging level to capture (default: DEBUG)
        log_to_console (bool): Whether to also log to console (default: False)
        max_bytes (int): Max size of log file before rotation in bytes (default: 10MB)
        backup_count (int): Number of backup files to keep (default: 5)
        
    Returns:
        logging.Logger: A configured logger instance
    """
    # Ensure logs directory exists
    logs_dir = os.path.join(os.getcwd(), 'logs')
    if not os.path.exists(logs_dir):
        os.makedirs(logs_dir)
        
    # Create log filename with date prefix for better organization
    # Store the current date as a datetime object
    current_date = datetime.now()
    # Format the date only when creating the filename
    today_formatted = current_date.strftime("%d-%m-%y")
    log_file = os.path.join(logs_dir, f'{logger_name}_{today_formatted}.log')
    
    logger = logging.getLogger(logger_name)
    logger.setLevel(log_level)
    
    # Clear any existing handlers
    if logger.handlers:
        logger.handlers = []
    
    # File handler with rotation - logs everything at specified level
    # Use ISO format in logs for better machine readability and standardization
    log_format = "%(asctime)s - Thread %(thread)d - %(levelname)s - %(message)s"
    
    # Replace FileHandler with RotatingFileHandler
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=max_bytes,
        backupCount=backup_count
    )
    file_handler.setLevel(log_level)
    # Use ISO format for timestamps in log files (YYYY-MM-DD HH:MM:SS)
    file_formatter = logging.Formatter(log_format, datefmt="%Y-%m-%d %H:%M:%S")
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    # Add console handler if requested
    if log_to_console:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        # For console display, you can use a more human-friendly format if needed
        console_formatter = logging.Formatter(log_format, datefmt="%d-%m-%Y %H:%M:%S")
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
    
    # Prevent log propagation to parent loggers
    logger.propagate = False
    
    return logger
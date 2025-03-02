import os
import logging
import warnings
from datetime import datetime

# Silence warnings (optional)
warnings.filterwarnings('ignore')

# Silence other Python loggers that might be printing to console
for log_name in ['urllib3', 'chardet', 'dns', 'imaplib', 'poplib']:
    logging.getLogger(log_name).setLevel(logging.CRITICAL)
    logging.getLogger(log_name).propagate = False

def P_Log(logger_name='evs', log_level=logging.DEBUG, log_to_console=False):
    """Configure application logging with file logging and optional console output
    
    Args:
        logger_name (str): Name of the logger and log file (default: 'evs')
        log_level (int): The minimum logging level to capture (default: DEBUG)
        log_to_console (bool): Whether to also log to console (default: False)
        
    Returns:
        logging.Logger: A configured logger instance
    """
    # Ensure logs directory exists
    logs_dir = os.path.join(os.getcwd(), 'logs')
    if not os.path.exists(logs_dir):
        os.makedirs(logs_dir)
        
    # Create log filename with date prefix for better organization
    today = datetime.now().strftime("%d-%m-%y")
    log_file = os.path.join(logs_dir, f'{logger_name}_{today}.log')
    
    logger = logging.getLogger(logger_name)
    logger.setLevel(log_level)
    
    # Clear any existing handlers
    if logger.handlers:
        logger.handlers = []
    
    # File handler - logs everything at specified level
    log_format = "%(asctime)s - Thread %(thread)d - %(levelname)s - %(message)s"
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(log_level)
    file_formatter = logging.Formatter(log_format, datefmt="%d-%m-%y %H:%M:%S")
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    # Add console handler if requested
    if log_to_console:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        console_handler.setFormatter(file_formatter)
        logger.addHandler(console_handler)
    
    # Prevent log propagation to parent loggers
    logger.propagate = False
    
    return logger
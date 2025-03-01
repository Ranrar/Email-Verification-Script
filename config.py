# config.py is a configuration file that contains settings and metadata for the script.

import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Tuple, Optional

@dataclass
class UserCredentials:
    USER_NAME: str = None
    USER_EMAIL: str = None

    def __post_init__(self):
        """Load credentials from database after initialization"""
        from database import Database
        try:
            db = Database(self)
            users = db.get_users()
            if users and len(users) > 0:
                # Use the first user's credentials
                self.USER_NAME = users[0][1]  # index 1 is name
                self.USER_EMAIL = users[0][3]  # index 3 is email
            else:
                # Fallback defaults if no users found
                self.USER_NAME = 'your_username'
                self.USER_EMAIL = 'your@email.com'
        except Exception as e:
            print(f"Warning: Could not load user credentials: {e}")
            # Set fallback values
            self.USER_NAME = 'your_username'
            self.USER_EMAIL = 'your@email.com'

class cat(Enum):
    """Short names for column categories"""
    CORE = "Core Information"
    SEC = "Security Checks"
    TECH = "Technical Details"
    PROT = "Protocol Status"
    META = "Metadata"

@dataclass
class LogColumn:
    """Configuration for a single log column"""
    name: str                  # Internal name (for reference)
    display_name: str          # Display name (shown in log)
    category: cat              # Column category
    index: int                 # Order in log display (lower numbers appear first)
    show: str = 'Y'           # Y for visible, N for hidden

    @property
    def visible(self) -> bool:
        return self.show.upper() == 'Y'

@dataclass
class Config:
    """Main configuration class"""
    # User credentials
    USER_CREDENTIALS: UserCredentials = field(default_factory=UserCredentials)

    # Rate Limiter Settings
    RATE_LIMIT_REQUESTS: int = 10
    RATE_LIMIT_WINDOW: int = 60
    
    # SMTP Settings
    SMTP_TIMEOUT: int = 10
    MAX_RETRIES: int = 3
    PORTS_TO_TRY: List[int] = field(default_factory=lambda: [25, 587, 465])
    CONNECTION_POOL_SIZE: int = 10

    # Rate Limiting Settings
    RATE_LIMITS: Dict[str, Tuple[int, int]] = field(
        default_factory=lambda: {
            'smtp_connections': (10, 60),    # 10 requests per minute
            'dns_lookups': (100, 60),        # 100 requests per minute
            'email_validations': (50, 60)    # 50 requests per minute
        }
    )

    # Number of log entries to display (0 for unlimited)
    LOG_DISPLAY_LIMIT: int = 50

    # Log Columns Configuration - Change display_name values to customize how columns appear in logs
    LOG_COLUMNS: Dict[str, LogColumn] = field(
        default_factory=lambda: {
            # Core Info - Basic information about the email check
            "ID": LogColumn(
                name="ID",                    # Don't change this
                display_name="#",           # Change this to customize how ID appears
                category=cat.META, 
                index=0,
                show='Y'                      # Y to show, N to hide
            ),
            "Time": LogColumn(
                name="Time",                  # Don't change this
                display_name="Time",          # Change this to customize timestamp display
                category=cat.META,
                index=1,
                show='Y'
            ),
            "Email": LogColumn(
                name="Email",                 # Internal name for database
                display_name="E-mail Address", # Display name for logs
                category=cat.CORE,
                index=2,
                show='Y'
            ),
            "Domain": LogColumn(
                name="Domain",                # Don't change this
                display_name="Domain Name",    # Change this to customize domain display
                category=cat.CORE,
                index=3,
                show='N'
            ),
            "Result": LogColumn(
                name="Result",                # Don't change this
                display_name="SMTP Status",    # Change this to customize result display
                category=cat.CORE,
                index=4,
                show='Y'
            ),
            "Error": LogColumn(
                name="Error",                 # Don't change this
                display_name="Error Info",     # Change this to customize error display
                category=cat.CORE,
                index=5,
                show='N'
            ),
            
            # Security - Email security check results
            "Disposable": LogColumn(
                name="Disposable",            # Don't change this
                display_name="Disposable",     # Change this to customize disposable check display
                category=cat.SEC,
                index=6,
                show='N'
            ),
            "SPF": LogColumn(
                name="SPF",                   # Don't change this
                display_name="SPF",           # Change this to customize SPF display
                category=cat.SEC,
                index=7,
                show='N'
            ),
            "DKIM": LogColumn(
                name="DKIM",                  # Don't change this
                display_name="DKIM",          # Change this to customize DKIM display
                category=cat.SEC,
                index=8,
                show='N'
            ),
            "Blacklist": LogColumn(
                name="Blacklist",             # Don't change this
                display_name="Blacklisted",    # Change this to customize blacklist display
                category=cat.SEC,
                index=9,
                show='N'
            ),
            
            # Technical - Server and protocol details
            "MX": LogColumn(
                name="MX",                    # Don't change this
                display_name="Mail Server",    # Change this to customize MX display
                category=cat.TECH,
                index=10,
                show='N'
            ),
            "Port": LogColumn(
                name="Port",                  # Don't change this
                display_name="SMTP Port",      # Change this to customize port display
                category=cat.TECH,
                index=11,
                show='N'
            ),
            "IP": LogColumn(
                name="IP",                    # Don't change this
                display_name="Server IP",      # Change this to customize IP display
                category=cat.TECH,
                index=12,
                show='N'
            ),
            "MXPref": LogColumn(
                name="MXPref",                # Don't change this
                display_name="MX Priority",    # Change this to customize MX priority display
                category=cat.TECH,
                index=13,
                show='N'
            ),
            "SMTP": LogColumn(
                name="SMTP",                  # Don't change this
                display_name="SMTP Info",      # Change this to customize SMTP info display
                category=cat.TECH,
                index=14,
                show='N'
            ),
            "VRFY": LogColumn(
                name="VRFY",                  # Don't change this
                display_name="VRFY Support",   # Change this to customize VRFY display
                category=cat.TECH,
                index=15,
                show='N'
            ),
            "Catch": LogColumn(
                name="Catch",                 # Don't change this
                display_name="Catch-all",      # Change this to customize catch-all display
                category=cat.TECH,
                index=16,
                show='Y'
            ),
            
            # Protocol - Additional protocol checks
            "IMAP": LogColumn(
                name="IMAP",                  # Don't change this
                display_name="IMAP",          # Change this to customize IMAP display
                category=cat.PROT,
                index=17,
                show='N'
            ),
            "IMAPInfo": LogColumn(
                name="IMAPInfo",              # Don't change this
                display_name="IMAP Details",   # Change this to customize IMAP details display
                category=cat.PROT,
                index=18,
                show='N'
            ),
            "POP3": LogColumn(
                name="POP3",                  # Don't change this
                display_name="POP3",          # Change this to customize POP3 display
                category=cat.PROT,
                index=19,
                show='N'
            ),
            "POP3Info": LogColumn(
                name="POP3Info",              # Don't change this
                display_name="POP3 Details",   # Change this to customize POP3 details display
                category=cat.PROT,
                index=20,
                show='N'
            ),
            
            # Metadata - Additional information
            "Count": LogColumn(
                name="Count",                 # Don't change this
                display_name="Checks",         # Change this to customize check count display
                category=cat.META,
                index=21,
                show='Y'
            )
        }
    )

    # Blacklist Settings
    BLACKLISTED_DOMAINS: Dict[str, List[str]] = field(
        default_factory=lambda: {
            "blacklisted.com": ["Spamhaus", "Barracuda", "SpamCop"],
            "baddomain.net": ["Spamhaus", "SORBS"],
            "malicious.org": ["SpamCop", "Spamhaus"]
        }
    )

    # Disposable Email Domains
    DISPOSABLE_DOMAINS: List[str] = field(
        default_factory=lambda: [
            "mailinator.com",
            "10minutemail.com",
            "tempmail.com",
            "temp-mail.org",
            "guerrillamail.com",
            "dispostable.com",
            "yopmail.com",
            "getnada.com",
            "tempinbox.com"
        ]
    )

    # User-Agent String
    USER_AGENT: str = 'EmailVerificationScript/1.0 (https://github.com/Ranrar/EVS)'

    # Database settings
    DB_PATH = 'email_verification.db'

    def get_visible_columns(self) -> Dict[str, LogColumn]:
        """Get only the visible columns"""
        return {key: col 
                for key, col in self.LOG_COLUMNS.items() 
                if col.show.upper() == 'Y'}

    def get_columns_by_category(self, category: cat) -> List[LogColumn]:
        """Get all columns in a specific category"""
        return [col for col in self.LOG_COLUMNS.values() 
                if col.category == category]

    def toggle_column_visibility(self, column_key: str) -> bool:
        """Toggle visibility of a specific column"""
        if column_key in self.LOG_COLUMNS:
            col = self.LOG_COLUMNS[column_key]
            col.show = 'N' if col.show.upper() == 'Y' else 'Y'
            return True
        return False
"""
Installer package for EVS application.
Provides installation, setup, and license agreement functionality.
"""

from .Installer import (
    Installer, InstallerUI, get_logger, 
    license_agreement_dialog, user_info_form, 
    show_error_message, success_message
)

# Define what gets exported with "from packages.installer import *"
__all__ = [
    'Installer', 
    'InstallerUI', 
    'get_logger',
    'license_agreement_dialog', 
    'user_info_form',
    'show_error_message', 
    'success_message'
]
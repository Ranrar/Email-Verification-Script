#!/usr/bin/env python3
# Email Verification Script
# Copyright (C) 2025 Kim Skov Rasmussen
#
# This work is licensed under the Creative Commons Attribution-NonCommercial-NoDerivatives 4.0 International License.
#
# You are free to use this software for academic research purposes only. However, you may not:
#
#    Use this software for commercial purposes.
#    Alter, transform, or build upon this work in any way (i.e., No Derivatives).
#    Redistribute this software or any modified versions of it without explicit permission from the author.
#
# Any redistribution, modification, or commercial use of this software is prohibited unless you have received explicit permission from the author.

from __future__ import annotations
from typing import Iterable
from packages.logger.logger import P_Log, LoggerManager, DEFAULT_LOGGER_NAME
from datetime import datetime
import atexit
import os
import json
import sys
import io
import webbrowser
import os
import re
import time
import json
import Core
import urwid
from concurrent.futures import ThreadPoolExecutor, as_completed

# cleanup old logs and organize log archive
LoggerManager.cleanup_old_logs(max_days=30)
LoggerManager.organize_log_archive()

logger = P_Log(log_to_console=False, split_by_level=True)

# Define path for the state file
STATE_FILE = os.path.join(os.getcwd(), 'app_state.json')

# Function to mark application as running
def mark_app_running():
    """Mark the application as currently running"""
    state = {
        'running': True,
        'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'pid': os.getpid()
    }
    try:
        with open(STATE_FILE, 'w') as f:
            json.dump(state, f)
        logger.info("Application started")
    except Exception as e:
        logger.error(f"Failed to create state file: {e}")

# Function to mark clean exit
def mark_clean_exit():
    """Mark the application as cleanly exited"""
    try:
        if os.path.exists(STATE_FILE):
            os.remove(STATE_FILE)
            logger.info("Application shutdown gracefully")
    except Exception as e:
        logger.error(f"Failed to remove state file: {e}")

# Function to check if previous run crashed
def check_previous_crash():
    """Check if previous run ended abnormally"""
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, 'r') as f:
                state = json.load(f)
            logger.warning(f"Previous session appears to have terminated abnormally at {state.get('start_time', 'unknown time')}")
            return True
        except json.JSONDecodeError:
            logger.warning("Previous session crashed (corrupted state file)")
            return True
        except IOError as e:
            logger.warning(f"Previous session crashed (cannot read state file: {e})")
            return True
    return False

def disconnect_signals(widget):
    """Recursively disconnect all signals from a widget and its children"""
    # Handle urwid container widgets
    if hasattr(widget, 'contents'):
        for w, _ in widget.contents:
            disconnect_signals(w)
    elif hasattr(widget, 'widget_list'):
        for w in widget.widget_list:
            disconnect_signals(w)
    elif hasattr(widget, 'original_widget'):
        disconnect_signals(widget.original_widget)
    elif hasattr(widget, '_w') and hasattr(widget._w, 'original_widget'):
        disconnect_signals(widget._w.original_widget)
        
    # Remove all signals from the widget's registry if it has any
    if hasattr(widget, '_urwid_signals'):
        for signal_name in list(widget._urwid_signals.keys()):
            widget._urwid_signals[signal_name] = []

# Now check for database existence
db_dir = os.path.join(os.getcwd(), 'DB')
db_path = os.path.join(db_dir, 'EVS.db')

if not os.path.exists(db_path):
    logger.info("Running installer...")
    from packages.installer.Installer import Installer
    installer = Installer()
    if installer.run_installation():
        logger.info("Installation completed successfully")
        # Refresh the config state to recognize the new database
        from config import config
        cfg = config()
        cfg.refresh_db_state()
        # Now initialize the system
        from Core import initialize_system
        if not initialize_system():
            logger.error("Failed to initialize system after installation")
            sys.exit(1)

# Now import other modules after dependencies and database are confirmed


# Register cleanup function to run at interpreter shutdown
def cleanup_logging():
    """Ensure all logging resources are freed on program exit"""
    try:
        # First close your specific loggers
        from packages.logger.logger import close_logger
        close_logger(logger)
        if hasattr(Core, 'logger'):
            close_logger(Core.logger)
        
        # Then shut down the entire logging system
        import logging
        logging.shutdown()
    except Exception as e:
        print(f"Error cleaning up loggers: {e}")

atexit.register(cleanup_logging)

# Add this near the top of your file after imports
menu_selection_history = {
    "main_menu": 2,  # Default to first menu item (position 2, after title and divider)
    "settings_menu": 1,  # Settings menu position (position 1, first item after divider)
}

# Add this near the top of your file with other global variables
menu_stack = []  # Stack to track navigation hierarchy
current_menu = "main"  # Track current menu level

# Add these classes at the top of your file after imports
class NoCursorSelectableIcon(urwid.SelectableIcon):
    def get_cursor_coords(self, size):
        # Always return None so no cursor is drawn
        return None

class CommandEdit(urwid.Edit):
    """Custom Edit widget that provides an 'enter' signal"""
    signals = ['enter']
    
    def keypress(self, size, key):
        if key == 'enter':
            urwid.emit_signal(self, 'enter', self, self.edit_text)
            return
        return super().keypress(size, key)
    
def confirmation_dialog(message, on_yes, on_no):
    """Create a simple yes/no confirmation dialog"""
    # Create the question text
    question = urwid.Text(message, align='center')
    
    # Create yes and no buttons
    yes_button = PlainButton("Yes")
    no_button = PlainButton("No")
    
    # Connect signals to buttons
    urwid.connect_signal(yes_button, 'click', on_yes)
    urwid.connect_signal(no_button, 'click', on_no)
    
    # Style the buttons
    yes_btn = urwid.AttrMap(yes_button, None, focus_map="menu_focus")
    no_btn = urwid.AttrMap(no_button, None, focus_map="menu_focus")
    
    # Create button row with padding between buttons
    button_row = urwid.Columns([
        ('weight', 1, urwid.Text("")),
        ('pack', yes_btn),
        ('fixed', 3, urwid.Text(" ")),  # Space between buttons
        ('pack', no_btn),
        ('weight', 1, urwid.Text(""))
    ])
    
    # Combine question and buttons into a pile
    dialog_pile = urwid.Pile([
        urwid.Divider(),
        question,
        urwid.Divider(),
        button_row,
        urwid.Divider()
    ])
    
    # Create a centered dialog box
    dialog = urwid.Filler(dialog_pile, 'middle')
    
    return apply_box_style(dialog, title="Confirmation")


# Add this after your CommandEdit class
class PlainButton(urwid.Button):
    button_left = urwid.Text("")
    button_right = urwid.Text("")
    
    def __init__(self, label, on_press=None, user_data=None):
        super().__init__("", on_press, user_data)
        # Use NoCursorSelectableIcon instead of default SelectableIcon
        self._w = urwid.AttrMap(NoCursorSelectableIcon(str(label)), None, focus_map='menu_focus')

choices = ["Terminal","Batch", "Email Validation Records", "Audit log", "Export", "Help", "Settings", "Exit"]

# Example usage in your menu function:
def menu(title: str, choices_: Iterable[str]) -> urwid.Widget:
    # Center the title text
    title_widget = urwid.Text(title, align='center')
    
    # Calculate the width needed for the longest menu item
    max_length = max(len(c) for c in choices_)
    menu_width = max_length + 4  # Add some padding
    
    # Create non-scrollable menu items
    menu_items = [title_widget, urwid.Divider()]
    
    # Create menu items with fixed-width centered container
    for c in choices_:
        # Use PlainButton instead of Button
        button = PlainButton(c)
        # Remove special case - all buttons go through item_chosen
        urwid.connect_signal(button, "click", lambda button, choice=c: item_chosen(button, choice))
        
        button_with_attr = urwid.AttrMap(button, None, "menu_focus")
        
        button_container = urwid.Columns([
            ('weight', 1, urwid.Text("")),
            ('fixed', menu_width, button_with_attr),
            ('weight', 1, urwid.Text(""))
        ])
        
        menu_items.append(button_container)
        menu_items.append(urwid.Divider())  # Add space between items
    
    cat_art = r"""
    )   _.
   (___)'' < meow!
   / ,_,/
  /'"\ )\
"""
    cat_widget = urwid.Text(("cat_art", cat_art))
    
    # Calculate height required by menu content
    menu_pile = urwid.Pile(menu_items)
    
    # Get the saved position or default to first menu item (position 2 after title and divider)
    try:
        position = menu_selection_history.get("main_menu", 2)  # Default to first item (position 2)
        # Make sure it's a valid position
        if position >= 0 and position < len(menu_items):
            menu_pile.focus_position = position
        else:
            # Fall back to first menu item
            menu_pile.focus_position = 2
    except (IndexError, AttributeError):
        # Fallback if position is invalid
        menu_pile.focus_position = 2  # Always set a default focus
        
    main_pile = urwid.Pile([
        ('pack', menu_pile),       # Menu takes only what it needs
        ('weight', 1, urwid.Filler(urwid.Text(""))),  # Empty space that expands
        ('pack', cat_widget)       # Cat art takes fixed height at bottom
    ])
    
    # Wrap the whole thing in a Filler
    main_widget = urwid.Filler(main_pile, valign='top')
    
    return main_widget

def menu_help():
    global current_menu, menu_stack
    
    # Update menu tracking
    if current_menu != "help":
        menu_stack.append(current_menu)
        current_menu = "help"
        
    help_text = """
▶ NAVIGATION
  • Use UP/DOWN arrow keys to navigate through menus and content
  • Press ENTER to select menu items or buttons
  • Press ESC from any screen to return to the main menu
  • Use PageUp/PageDown for faster scrolling in long content areas

▶ MAIN MENU OPTIONS
  • Terminal        - Access command-line interface mode
  • Batch           - Process and manage batch email validations
  • Email Validation Records - View history of email verifications
  • Audit log       - View application logs and activity history
  • Export          - Export email validation data in various formats
  • Help            - Display this help information
  • Settings        - Not working yet
  • Exit            - Quit the application

▶ BASIC USAGE
  Simply enter one or more email addresses separated by commas to verify them:
  example@domain.com, test@example.org

▶ AVAILABLE COMMANDS (Terminal Mode)
  help             Display this help information
  show log         Display email validation history with results
  show log all     Display all email records including batch records
  show batch       List all batches and prompt for a batch ID to view
  show batch <ID>  Display all records from a specific batch directly
  clear log        Delete all non-batch validation history
  clear log all    Delete ALL validation history including batch records
  clear batch      Delete a specific batch and its records
  settings         Not working yet
  clear            Clear the terminal screen
  read more        Open the detailed documentation in your browser
  who am i         Display current user information
  refresh          Refresh database connection and clear cache
  debug log        Show raw database records for debugging
  exit             Return to main menu

▶ VALIDATION INFORMATION
  Each validation provides:
  • MX record verification (checks if domain can receive email)
  • SMTP connection testing (verifies mailbox existence)
  • Catch-all detection (identifies domains accepting all emails)
  • SPF and DKIM record checking (email security verification)
  • Disposable email detection (identifies temporary email services)
  • Blacklist checking (identifies potentially problematic domains)
  • IMAP/POP3 availability (additional mail server information)

▶ BATCH OPERATIONS
  • Create new batches from text/CSV files
  • View batch history and processing results
  • Display detailed validation results for specific batches
  • Track success rates and processing times

▶ EXPORT OPTIONS
  • Export by Date Range - Export records created between specified dates
  • Export by Batch - Export all records from a specific batch
  • Export by Domain - Export records for specific email domains
  • Export by Confidence Level - Export based on validation confidence
  • Export All Records - Export the complete validation database
  • Export by Field Categories - Selectively export fields by category:
    - Metadata: Timestamp, batch information, source
    - Core: Email format, domain, mailbox validation
    - Security: SPF, DKIM, blacklist status
    - Technical: MX records, catch-all status
    - Protocol: IMAP/POP3 availability

▶ CUSTOM FILTERING
  • Filter by Date Range - View records from specific time periods
  • Filter by Domain - Focus on specific email domains
  • Filter by Confidence Level - Filter by validation quality
  • Filter by Email Text - Search for text within email addresses
"""
    # Create a ListBox with the help text
    help_contents = urwid.SimpleListWalker([urwid.Text(help_text)])
    help_listbox = urwid.ListBox(help_contents)
    
    # Add ScrollBar directly to the ListBox
    help_area_with_scrollbar = urwid.ScrollBar(help_listbox)
    
    # Wrap the ScrollBar in a BoxAdapter to give it an explicit height
    help_box = urwid.BoxAdapter(help_area_with_scrollbar, 25)  # 25 lines tall
    
    # Back button
    done = PlainButton("Back [esc]")
    urwid.connect_signal(done, "click", go_back_one_level)
    
    # Create compact button container to save vertical space
    button_container = urwid.Columns([
        ('weight', 1, urwid.Text("")),
        ('pack', urwid.AttrMap(done, None, focus_map="menu_focus")),
        ('weight', 1, urwid.Text(""))
    ])
    
    # Create the help view
    help_view = urwid.Pile([
        help_box,  # The help text with scrollbar
        urwid.Divider(),
        button_container,
        urwid.Divider()
    ])
    
    # Update the main widget with the boxed style
    main.original_widget = apply_box_style(
        urwid.Filler(help_view, valign='top', top=0, bottom=0), 
        title="Help"
    )

# Add this helper function to apply consistent styling to all screens
def apply_box_style(content, title="Email Verification Script"):
    """Apply consistent LineBox styling to any content"""
    boxed_content = urwid.LineBox(content, title=title)
    return urwid.Padding(boxed_content, left=1, right=1)

# Then modify go_back_to_main to use this style
def go_back_to_main(button=None):
    # Create main menu and apply box style
    main_menu = menu(start_text(), choices)
    main.original_widget = apply_box_style(main_menu)
    
def terminal_function():
    """Display interactive terminal that works like a traditional command prompt"""
    global current_menu, menu_stack
    
    # Update menu tracking
    if current_menu != "terminal":
        menu_stack.append(current_menu)
        current_menu = "terminal"
    
    # Start with just a welcome message
    history_items = [
        urwid.Text("Welcome to the terminal."),
        urwid.Text("")  # Empty line for spacing
    ]
    
    # Create the prompt edit widget
    prompt_text = "> "
    input_edit = CommandEdit(prompt_text)
    input_edit.edit_text = ""  # Start with empty input
    
    # Add the prompt to the history items
    history_items.append(input_edit)
    
    # Create the list walker and list box
    history_walker = urwid.SimpleListWalker(history_items)
    terminal_list = urwid.ListBox(history_walker)
    
    # Add ScrollBar directly to the ListBox
    terminal_area_with_scrollbar = urwid.ScrollBar(terminal_list)
    
    # Fix: Wrap the ScrollBar in a BoxAdapter to give it an explicit height
    terminal_box = urwid.BoxAdapter(terminal_area_with_scrollbar, 25)  # 25 lines tall
    
    def handle_enter(edit, text):
        # Process the command when Enter is pressed
        if text.strip() == "exit":
            go_back_to_main()
            return
        
        # Update the prompt text to show the command
        history_walker[-1] = urwid.Text(f"{prompt_text}{text}")
        
        # Limit history size to prevent memory leaks (keep last 1000 items)
        MAX_HISTORY_ITEMS = 1000
        if len(history_walker) > MAX_HISTORY_ITEMS:
            # Remove oldest items but keep first welcome message
            items_to_remove = len(history_walker) - MAX_HISTORY_ITEMS
            del history_walker[1:items_to_remove+1]
            logger.debug(f"Terminal history trimmed, removed {items_to_remove} old entries")
        
        # Process the command and show the result
        if text.strip() == "":
            result = "Please enter a command."
        elif text.strip() == "help":
            result = """
▶ AVAILABLE COMMANDS (Terminal Mode)
  help             Display this help information
  show log         Display email validation history with results
  show log all     Display all email records including batch records
  show batch       List all batches and prompt for a batch ID to view
  show batch <ID>  Display all records from a specific batch directly
  clear log        Delete all non-batch validation history
  clear log all    Delete ALL validation history including batch records
  clear batch      Delete a specific batch and its records
  settings         Not working yet
  clear            Clear the terminal screen
  read more        Open the detailed documentation in your browser
  who am i         Display current user information
  refresh          Refresh database connection and clear cache
  debug log        Show raw database records for debugging
  exit             Return to main menu

▶ EMAIL VALIDATION
  Simply enter one or more email addresses separated by commas to verify them:
  example@domain.com, test@example.org
"""
        elif text.strip() == "show log":
            old_stdout = sys.stdout
            result_capture = io.StringIO()
            sys.stdout = result_capture
            Core.display_logs_standalone()
            sys.stdout = old_stdout
            result = result_capture.getvalue()

        elif text.strip() == "show log all":
            old_stdout = sys.stdout
            result_capture = io.StringIO()
            sys.stdout = result_capture
            Core.display_logs_all()
            sys.stdout = old_stdout
            result = result_capture.getvalue()

        elif text.strip().lower() == "show batch" or text.strip().lower().startswith("show batch "):
            # Check if just "show batch" without an ID
            if text.strip().lower() == "show batch":
                # Get list of batches
                batches = Core.list_batches()

                if not batches:
                    result = "No batches found in database."
                    logger.info("No batches found when attempting to show batches")
                else:
                    # Display the batch list
                    history_walker.append(urwid.Text("\nAvailable Batches:"))
                    header = f"{'ID':<5} | {'Name':<30} | {'Created':<19} | {'Total':<6} | {'Processed':<9}"
                    history_walker.append(urwid.Text(header))
                    history_walker.append(urwid.Text("-" * len(header)))

                    for batch in batches:
                        created_at = batch['created_at'][:19] if batch['created_at'] else "N/A"  # Trim to just show date and time
                        batch_line = f"{batch['id']:<5} | {batch['batch_name'][:30]:<30} | {created_at:<19} | {batch['total_emails']:<6} | {batch['processed_emails']:<9}"
                        history_walker.append(urwid.Text(batch_line))

                    history_walker.append(urwid.Text("\nEnter the batch ID to view, or 'cancel' to abort:"))

                    # Create an edit widget for the user to enter the batch ID
                    batch_edit = CommandEdit("> ")
                    history_walker.append(batch_edit)
                    terminal_list.focus_position = len(history_walker) - 1

                    def handle_batch_view_id(widget, text):
                        if text.strip().lower() == 'cancel':
                            history_walker.append(urwid.Text("Batch viewing cancelled."))
                            logger.info("User cancelled batch viewing")

                            # Add a new input line
                            history_walker.append(urwid.Text(""))
                            new_edit = CommandEdit(prompt_text)
                            history_walker.append(new_edit)
                            urwid.connect_signal(new_edit, 'enter', handle_enter)
                            terminal_list.focus_position = len(history_walker) - 1
                            return

                        try:
                            batch_id = int(text.strip())

                            # Check if the batch exists before proceeding
                            valid_batch = False
                            for batch in batches:
                                if batch['id'] == batch_id:
                                    valid_batch = True
                                    break

                            if not valid_batch:
                                history_walker.append(urwid.Text(f"Error: Batch ID {batch_id} does not exist in the database."))
                                history_walker.append(urwid.Text("\nEnter the batch ID to view, or 'cancel' to abort:"))

                                # Create a new edit widget for another attempt
                                batch_edit = CommandEdit("> ")
                                history_walker.append(batch_edit)
                                terminal_list.focus_position = len(history_walker) - 1
                                urwid.connect_signal(batch_edit, 'enter', handle_batch_view_id)
                                return

                            # If we get here, the batch exists - show its results directly in the terminal
                            history_walker.append(urwid.Text(f"Showing results for batch ID: {batch_id}"))

                            # Get batch results
                            old_stdout = sys.stdout
                            result_capture = io.StringIO()
                            sys.stdout = result_capture
                            Core.display_logs(batch_id)
                            sys.stdout = old_stdout
                            captured_output = result_capture.getvalue()

                            # Add the results to the terminal
                            if captured_output.strip():
                                # Split by lines and add each line as a separate text widget
                                for line in captured_output.strip().split('\n'):
                                    history_walker.append(urwid.Text(line))
                            else:
                                history_walker.append(urwid.Text(f"No display data found for batch ID {batch_id}"))

                            # Add a new input line
                            history_walker.append(urwid.Text(""))
                            new_edit = CommandEdit(prompt_text)
                            history_walker.append(new_edit)
                            urwid.connect_signal(new_edit, 'enter', handle_enter)
                            terminal_list.focus_position = len(history_walker) - 1

                        except ValueError:
                            history_walker.append(urwid.Text(f"Invalid batch ID: {text.strip()}. Please enter a number."))
                            history_walker.append(urwid.Text("\nEnter the batch ID to view, or 'cancel' to abort:"))

                            # Create a new edit widget for another attempt
                            batch_edit = CommandEdit("> ")
                            history_walker.append(batch_edit)
                            terminal_list.focus_position = len(history_walker) - 1
                            urwid.connect_signal(batch_edit, 'enter', handle_batch_view_id)

                    urwid.connect_signal(batch_edit, 'enter', handle_batch_view_id)
                    return
            else:
                # Handle the "show batch X" case with ID
                try:
                    batch_id = int(text.strip().lower().replace("show batch ", "").strip())

                    # Log the command
                    logger.info(f"Terminal UI: User requested to show batch ID {batch_id}")

                    # Show batch results directly in the terminal (consistent with show batch command)
                    history_walker.append(urwid.Text(f"Showing results for batch ID: {batch_id}"))
            
                    # Get batch results
                    old_stdout = sys.stdout
                    result_capture = io.StringIO()
                    sys.stdout = result_capture
                    Core.display_logs(batch_id)
                    sys.stdout = old_stdout
                    captured_output = result_capture.getvalue()
            
                    # Add the results to the terminal
                    if captured_output.strip():
                        # Split by lines and add each line as a separate text widget
                        for line in captured_output.strip().split('\n'):
                            history_walker.append(urwid.Text(line))
                    else:
                        history_walker.append(urwid.Text(f"No display data found for batch ID {batch_id}"))
            
                    # Add a new input line
                    history_walker.append(urwid.Text(""))
                    new_edit = CommandEdit(prompt_text)
                    history_walker.append(new_edit)
                    urwid.connect_signal(new_edit, 'enter', handle_enter)
                    terminal_list.focus_position = len(history_walker) - 1
            
                    # Return early since we've added our own command input
                    return
            
                except ValueError:
                    result = "Invalid batch ID. Please enter a numeric ID: show batch <ID>"
                    logger.warning(f"Terminal UI: Invalid batch ID entered: {text}")

        elif text.strip() == "clear log":
            logger.info("Terminal UI: User requested to clear the log.")
    
            # First, update the prompt text to show the command (consistent with other commands)
            history_walker[-1] = urwid.Text(f"{prompt_text}{text}")
    
            # Store the terminal container BEFORE adding a dialog
            original_terminal_container = main.original_widget
    
            def on_clear_confirm(button):
                # Call clear_log and process result
                clear_result = Core.clear_log_standalone()()
                if clear_result['success']:
                    if clear_result['status'] == 'empty':
                        result_text = "Database is already empty - nothing to clear."
                    else:
                        result_text = f"{clear_result['message']}."
                else:
                    result_text = f"Error: {clear_result['message']}"
        
                # Restore the terminal
                main.original_widget = original_terminal_container
        
                # Add the result
                history_walker.append(urwid.Text(result_text))
        
                # NOW add a new input line (only once, after the result)
                history_walker.append(urwid.Text(""))
                new_edit = CommandEdit(prompt_text)
                history_walker.append(new_edit)
                urwid.connect_signal(new_edit, 'enter', handle_enter)
                terminal_list.focus_position = len(history_walker) - 1
    
            def on_clear_cancel(button):
                # Restore the terminal
                main.original_widget = original_terminal_container
        
                # Add the cancelled message
                history_walker.append(urwid.Text("Operation cancelled - no logs were cleared."))
                logger.info("Terminal UI: User cancelled the clear log operation.")
        
                # NOW add a new input line (only once, after the result)
                history_walker.append(urwid.Text(""))
                new_edit = CommandEdit(prompt_text)
                history_walker.append(new_edit)
                urwid.connect_signal(new_edit, 'enter', handle_enter)
                terminal_list.focus_position = len(history_walker) - 1
    
                # Create and show dialog
            confirm_dialog = confirmation_dialog(
                f"There are {Core.non_batch_record_count()} standalone email logs in the database.\n"
                "Are you sure you want to clear all non-batch records?\n"
                "This cannot be undone.\n\n"
                "Note: Records associated with batches will not be deleted.",
                on_clear_confirm,
                on_clear_cancel
)
            # Replace the terminal with the dialog
            main.original_widget = confirm_dialog
            # Set result to None to avoid UnboundLocalError
            result = None  # This line is crucial for avoiding the error

            # Return early, since we've handled the input processing in the callbacks
            return

        elif text.strip() == "clear log all":
            logger.info("Terminal UI: User requested to clear ALL logs including batch records.")
    
            # First, update the prompt text to show the command
            history_walker[-1] = urwid.Text(f"{prompt_text}{text}")
    
            # Store the terminal container BEFORE adding a dialog
            original_terminal_container = main.original_widget
    
            def on_clear_all_confirm(button):
                # Call clear_log_all and process result
                clear_result = Core.clear_log_all()
                if clear_result['success']:
                    if clear_result['status'] == 'empty':
                        result_text = "Database is already empty - nothing to clear."
                    else:
                        result_text = f"{clear_result['message']}."
                else:
                    result_text = f"Error: {clear_result['message']}"
        
                # Restore the terminal
                main.original_widget = original_terminal_container
        
                # Add the result
                history_walker.append(urwid.Text(result_text))
        
                # NOW add a new input line
                history_walker.append(urwid.Text(""))
                new_edit = CommandEdit(prompt_text)
                history_walker.append(new_edit)
                urwid.connect_signal(new_edit, 'enter', handle_enter)
                terminal_list.focus_position = len(history_walker) - 1
    
            def on_clear_all_cancel(button):
                # Restore the terminal
                main.original_widget = original_terminal_container
        
                # Add the cancelled message
                history_walker.append(urwid.Text("Operation cancelled - no logs were cleared."))
                logger.info("Terminal UI: User cancelled the clear all logs operation.")
        
                # NOW add a new input line
                history_walker.append(urwid.Text(""))
                new_edit = CommandEdit(prompt_text)
                history_walker.append(new_edit)
                urwid.connect_signal(new_edit, 'enter', handle_enter)
                terminal_list.focus_position = len(history_walker) - 1
    
            # Create and show dialog
            confirm_dialog = confirmation_dialog(
                f"There are {Core.record_count()} email logs in the database (including {Core.non_batch_record_count()} standalone and batch records).\n"
                "Are you sure you want to clear ALL records including batch data?\n"
                "This cannot be undone.\n\n"
                "WARNING: This will delete ALL records, including batch history and information!",
                on_clear_all_confirm,
                on_clear_all_cancel
            )
            # Replace the terminal with the dialog
            main.original_widget = confirm_dialog
            # Set result to None to avoid UnboundLocalError
            result = None
    
            # Return early, since we've handled the input processing in the callbacks
            return

        elif text.strip().lower() == "clear batch":
            logger.info("Terminal UI: User requested to clear a batch.")
    
            # First, update the prompt text to show the command
            history_walker[-1] = urwid.Text(f"{prompt_text}{text}")
    
            # Get list of batches
            batches = Core.list_batches()
    
            if not batches:
                history_walker.append(urwid.Text("No batches found in database."))
                logger.info("No batches found when attempting to clear batch")
        
                # Add a new input line
                history_walker.append(urwid.Text(""))
                new_edit = CommandEdit(prompt_text)
                history_walker.append(new_edit)
                urwid.connect_signal(new_edit, 'enter', handle_enter)
                terminal_list.focus_position = len(history_walker) - 1
                return
    
            # Display the batch list
            history_walker.append(urwid.Text("\nAvailable Batches:"))
            header = f"{'ID':<5} | {'Name':<30} | {'Created':<19} | {'Total':<6} | {'Processed':<9}"
            history_walker.append(urwid.Text(header))
            history_walker.append(urwid.Text("-" * len(header))
)
            for batch in batches:
                created_at = batch['created_at'][:19] if batch['created_at'] else "N/A"  # Trim to just show date and time
                batch_line = f"{batch['id']:<5} | {batch['batch_name'][:30]:<30} | {created_at:<19} | {batch['total_emails']:<6} | {batch['processed_emails']:<9}"
                history_walker.append(urwid.Text(batch_line))
    
            history_walker.append(urwid.Text("\nEnter the batch ID to delete, or 'cancel' to abort:"))
    
            # Create an edit widget for the user to enter the batch ID
            batch_edit = CommandEdit("> ")
            history_walker.append(batch_edit)
            terminal_list.focus_position = len(history_walker) - 1
    
            def handle_batch_id(widget, text):
                if text.strip().lower() == 'cancel':
                    history_walker.append(urwid.Text("Batch deletion cancelled."))
                    logger.info("User cancelled batch deletion")
            
                    # Add a new input line
                    history_walker.append(urwid.Text(""))
                    new_edit = CommandEdit(prompt_text)
                    history_walker.append(new_edit)
                    urwid.connect_signal(new_edit, 'enter', handle_enter)
                    terminal_list.focus_position = len(history_walker) - 1
                    return
        
                try:
                    batch_id = int(text.strip())
                    
                    # Check if the batch exists before proceeding
                    valid_batch = False
                    batch_name = "Unknown"
                    for batch in batches:
                        if batch['id'] == batch_id:
                            valid_batch = True
                            batch_name = batch['batch_name']
                            break
                    
                    if not valid_batch:
                        history_walker.append(urwid.Text(f"Error: Batch ID {batch_id} does not exist in the database."))
                        history_walker.append(urwid.Text("\nEnter the batch ID to delete, or 'cancel' to abort:"))
                        
                        # Create a new edit widget for another attempt
                        batch_edit = CommandEdit("> ")
                        history_walker.append(batch_edit)
                        terminal_list.focus_position = len(history_walker) - 1
                        urwid.connect_signal(batch_edit, 'enter', handle_batch_id)
                        return
                    
                    # If we get here, the batch exists - proceed with confirmation
                    history_walker.append(urwid.Text(f"Selected batch ID: {batch_id}"))
                    
                    # Get record count for this batch
                    record_count = Core.lines_in_batch(batch_id)
                    
                    # Show confirmation dialog
                    original_terminal_container = main.original_widget
                    
                    def on_batch_clear_confirm(button):
                        # Call clear_batch and process result
                        clear_result = Core.clear_batch(batch_id)
                        if clear_result['success']:
                            if clear_result['status'] == 'empty':
                                result_text = f"Batch '{batch_name}' was empty. Batch info deleted."
                            elif clear_result['status'] == 'not_found':
                                result_text = f"Batch ID {batch_id} not found."
                            else:
                                result_text = f"{clear_result['message']}."
                        else:
                            result_text = f"Error: {clear_result['message']}"
                        
                        # Restore the terminal
                        main.original_widget = original_terminal_container
                        
                        # Add the result
                        history_walker.append(urwid.Text(result_text))
                        
                        # Add a new input line
                        history_walker.append(urwid.Text(""))
                        new_edit = CommandEdit(prompt_text)
                        history_walker.append(new_edit)
                        urwid.connect_signal(new_edit, 'enter', handle_enter)
                        terminal_list.focus_position = len(history_walker) - 1
                    
                    def on_batch_clear_cancel(button):
                        # Restore the terminal
                        main.original_widget = original_terminal_container
                        
                        # Add the cancelled message
                        history_walker.append(urwid.Text("Operation cancelled - batch was not cleared."))
                        logger.info(f"User cancelled the clear batch operation for batch ID {batch_id}")
                        
                        # Add a new input line
                        history_walker.append(urwid.Text(""))
                        new_edit = CommandEdit(prompt_text)
                        history_walker.append(new_edit)
                        urwid.connect_signal(new_edit, 'enter', handle_enter)
                        terminal_list.focus_position = len(history_walker) - 1
                    
                    # Create and show dialog
                    confirm_dialog = confirmation_dialog(
                        f"Are you sure you want to delete batch '{batch_name}' (ID: {batch_id})?\n\n"
                        f"This will permanently delete {record_count} email validation records\n"
                        f"and remove the batch information from the database.\n\n"
                        "This action cannot be undone.",
                        on_batch_clear_confirm,
                        on_batch_clear_cancel
                    )
                    
                    # Replace the terminal with the dialog
                    main.original_widget = confirm_dialog
                except ValueError:
                    history_walker.append(urwid.Text(f"Invalid batch ID: {text.strip()}. Please enter a number."))
                    history_walker.append(urwid.Text("\nEnter the batch ID to delete, or 'cancel' to abort:"))
                    
                    # Create a new edit widget for another attempt
                    batch_edit = CommandEdit("> ")
                    history_walker.append(batch_edit)
                    terminal_list.focus_position = len(history_walker) - 1
                    urwid.connect_signal(batch_edit, 'enter', handle_batch_id)
            urwid.connect_signal(batch_edit, 'enter', handle_batch_id)
            return

            # Return early, since we've handled the input processing in the callbacks
            return
        elif text.strip() == "read more":
            file_path = os.path.join(os.getcwd(), "README.md")
            webbrowser.open(file_path)
            result = "Opening README.md"
        elif text.strip().lower() == "settings":
            loop = get_main_loop()
            if loop:
                loop.set_alarm_in(0.1, lambda *args: show_settings())
            go_back_to_main()
            return
        elif text.strip().lower() == "refresh":
            old_stdout = sys.stdout
            result_capture = io.StringIO()
            sys.stdout = result_capture
            success = Core.refresh_db_state()  # Capture the return value
            sys.stdout = old_stdout
            captured_output = result_capture.getvalue().strip()  # Get actual output from function
            if captured_output:
                result = captured_output
            else:
                result = "Refreshing the database connection and clearing the cache." if success else "Error refreshing database. See logs for details."    
            logger.debug(f"Terminal UI: Database refresh result: {success}")
        elif text.strip().lower() == "debug log":
            old_stdout = sys.stdout
            result_capture = io.StringIO()
            sys.stdout = result_capture
            Core.debug_show_records()
            sys.stdout = old_stdout
            result = result_capture.getvalue() or "Debugging the database connection."
            logger.debug("Debugging the database connection.")
        elif text.strip() == "who am i":
            old_stdout = sys.stdout
            result_capture = io.StringIO()
            sys.stdout = result_capture
            Core.get_user_info()
            sys.stdout = old_stdout
            result = result_capture.getvalue()
        elif text.lower() == "clear":
            # Just clear the terminal
            history_walker.clear()
            history_walker.append(urwid.Text("Terminal cleared."))
            history_walker.append(urwid.Text(""))
            new_edit = CommandEdit(prompt_text)
            history_walker.append(new_edit)
            urwid.connect_signal(new_edit, 'enter', handle_enter)
            terminal_list.focus_position = len(history_walker) - 1
            return
        else:
            # Check if it's an email or list of emails
            # Use delimiter patterns to split the input text
            delimiter_pattern = re.compile(r'[,;\s\n]+')  # Matches commas, semicolons, whitespace, newlines
            raw_emails = delimiter_pattern.split(text)

            # Filter and validate using Core's pattern
            emails = []
            for email in raw_emails:
                email = email.strip()
                if email and Core.EMAIL_PATTERN.match(email):
                    emails.append(email)

            if emails:  # If any valid emails were found
                # It's an email validation request
                logger.info(f"Terminal UI: Processing {len(emails)} email(s) for validation")
                try:
                    # Debug log before validation
                    for email in emails:
                        logger.debug(f"Terminal UI: Validating email: {email}")
                    
                    # Add a more informative "Processing..." message with animation
                    processing_msg = urwid.Text(f"Processing {len(emails)} email(s)... This may take a few seconds")
                    history_walker.append(processing_msg)
                    
                    # Force update the display before continuing
                    loop = get_main_loop()
                    if loop:
                        loop.draw_screen()
                    
                    # Capture all stdout output from Core.validate_emails
                    old_stdout = sys.stdout
                    result_capture = io.StringIO()
                    sys.stdout = result_capture
                    
                    # Use validate_emails for parallel processing
                    logger.debug(f"Terminal UI: Calling Core.validate_emails() with {len(emails)} emails")
                    results = Core.validate_emails(emails)
                    
                    # Get any output that was printed to stdout
                    sys.stdout = old_stdout
                    stdout_output = result_capture.getvalue()
                    
                    logger.debug(f"Terminal UI: Received {len(results)} results from validation")
                    
                    # Replace the processing message with a completion message
                    history_walker[-1] = urwid.Text(f"Completed processing {len(emails)} email(s)")
                    
                    # Add any captured stdout as text widgets, line by line
                    if stdout_output:
                        for line in re.split(r'\r\n|\r|\n', stdout_output.strip()):
                            if line.strip():
                                history_walker.append(urwid.Text(line))
                    
                    # Log the results received from Core
                    for email, result in zip(emails, results):
                        logger.debug(f"Terminal UI: Result for {email}: {result}")
                        # Add each result individually as a separate Text widget
                        history_walker.append(urwid.Text(f"{email}: {result}"))
                    result = ""
                    
                    logger.info(f"Terminal UI: Email validation complete for {', '.join(emails)}")
                except Exception as e:
                    logger.error(f"Terminal UI: Email validation error: {e}", exc_info=True)
                    result = f"Error during validation: {str(e)}"
            else:
                # Unknown command
                result = f"Unknown command. Type 'help' for available commands."
                logger.debug(f"Unknown terminal command: {text}")
        
        # Add result to history
        if result:  # Only add non-empty results
            history_walker.append(urwid.Text(result))
            # history_walker.append(urwid.Text(""))

        # Create a new command prompt and add it to history
        new_edit = CommandEdit(prompt_text)
        history_walker.append(new_edit)
        urwid.connect_signal(new_edit, 'enter', handle_enter)
        terminal_list.focus_position = len(history_walker) - 1
    
    # Connect the initial edit widget to the enter event
    urwid.connect_signal(input_edit, 'enter', handle_enter)
    
    # Back button styled like main menu buttons
    done = PlainButton("Back [esc]")
    urwid.connect_signal(done, "click", go_back_one_level)
    
    # Create compact button container to save vertical space
    button_container = urwid.Columns([
        ('weight', 1, urwid.Text("")),
        ('pack', urwid.AttrMap(done, None, focus_map="menu_focus")),
        ('weight', 1, urwid.Text(""))
    ])
    
    # Create the terminal view
    terminal_view = urwid.Pile([
        terminal_box,  # The terminal with scrollbar
        urwid.Divider(),
        button_container,
        urwid.Divider()
    ])
    
    # Set focus to the terminal so the command prompt is active
    terminal_view.focus_position = 0
    
    # Update the main widget with the boxed style
    main.original_widget = apply_box_style(
        urwid.Filler(terminal_view, valign='top', top=0, bottom=0), 
        title="Terminal"
    )

# Modify your item_chosen function to call terminal_function when selected
def item_chosen(button: urwid.Button, choice: str) -> None:
    # Get the index of choice in choices list to save position
    if choice in choices:
        menu_selection_history["main_menu"] = choices.index(choice) * 2 + 2  # +2 for title and divider
    
    if choice == "Terminal":
        terminal_function()
    elif choice == "Settings":
        show_settings()
    elif choice == "Help":
        menu_help()
    elif choice == "Email Validation Records":
        show_validation_records()
    elif choice == "Export":
        show_export()
    elif choice == "Batch":
        show_batch_operations()
    elif choice == "Audit log":
        show_audit_log()
    elif choice == "Exit":
        exit_program(button)
    else:
        # Default handler for unimplemented options
        response = urwid.Text(["> ", choice, " (not yet implemented)\n"])
        done = PlainButton("Back [esc]")
        urwid.connect_signal(done, "click", go_back_one_level)
        main.original_widget = urwid.Filler(
            urwid.Pile([
                response,
                urwid.AttrMap(done, None, focus_map="menu_focus"),
            ])
        )

# Add to startup code (after logger initialization)
crash_detected = check_previous_crash()
mark_app_running()

# Register cleanup for regular Python exit cases
atexit.register(mark_clean_exit)

# Modify your exit_program function in Main.py
def exit_program(button: urwid.Button = None) -> None:
    """Properly shut down the application including logging"""
    try:
        # Mark clean exit
        mark_clean_exit()
        
        # Shutdown Core resources - Core.shutdown() already calls refresh_db_state()
        if 'Core' in globals() and hasattr(Core, 'shutdown') and callable(Core.shutdown):
            logger.debug("Calling Core.shutdown() to clean up resources")
            Core.shutdown()
        else:
            # Only call refresh_db_state directly if Core.shutdown() wasn't called
            from config import config
            cfg = config()
            if hasattr(cfg, 'refresh_db_state'):
                cfg.refresh_db_state()
        
        # Clean up logging last
        cleanup_logging()
        
    except Exception as e:
        print(f"Error during shutdown cleanup: {e}")
    finally:
        # Exit the main loop
        raise urwid.ExitMainLoop()

# Fix the show_settings function
def show_settings():
    """Display main settings categories that lead to submenus"""
    global current_menu, menu_stack
    
    # Update menu tracking
    if current_menu != "settings":
        menu_stack.append(current_menu)
        current_menu = "settings"
    
    # Define all settings categories
    categories = [
        ("General Settings", show_general_settings),
        ("User Settings", show_user_settings),
        ("SMTP Settings", show_smtp_settings),
        ("Rate Limits", show_rate_limits),
        ("Validation & Confidence", show_validation_and_confidence),
        ("Thread Pool Settings", show_thread_pool_settings),
        ("Cache Settings", show_cache_settings),
        ("DNS Settings", show_dns_settings),
        ("Protocol Settings", show_protocol_settings),
        ("Security Settings", show_security_settings),
        ("Logging Fields", show_logging_fields)
    ]
    
    # Calculate the width needed for the longest menu item
    max_length = max(len(category[0]) for category in categories)
    menu_width = max_length + 4  # Add some padding
    
    # Create non-scrollable menu items - start with just a divider
    menu_items = [urwid.Divider()]
    
    # Create menu items with fixed-width centered container
    for i, (category_name, callback) in enumerate(categories):
        button = PlainButton(category_name)
        # Store category position when clicked
        urwid.connect_signal(button, 'click', lambda btn, pos=i, cb=callback: category_selected(pos, cb))
        
        button_with_attr = urwid.AttrMap(button, None, focus_map="menu_focus")
        
        button_container = urwid.Columns([
            ('weight', 1, urwid.Text("")),
            ('fixed', menu_width, button_with_attr),
            ('weight', 1, urwid.Text(""))
        ])
        
        menu_items.append(button_container)
        menu_items.append(urwid.Divider())  # Add space between items
    
    # Back button styled like main menu buttons
    back_button = PlainButton("Back [esc]")
    urwid.connect_signal(back_button, 'click', go_back_one_level)
    
    # Create centered button container for back button
    back_container = urwid.Columns([
        ('weight', 1, urwid.Text("")),
        ('fixed', menu_width, urwid.AttrMap(back_button, None, focus_map="menu_focus")),
        ('weight', 1, urwid.Text(""))
    ])
    
    # Add back button to menu items
    menu_items.append(back_container)
    menu_items.append(urwid.Divider())
    
    # Create the settings menu pile
    settings_pile = urwid.Pile(menu_items)
    
    # Apply the saved focus position directly - IMPORTANT FIX
    try:
        position = menu_selection_history.get("settings_menu", 1)  # Default to first item (position 1)
        # Make sure it's a valid position
        if position >= 0 and position < len(menu_items):
            settings_pile.focus_position = position
        else:
            # Fall back to first menu item
            settings_pile.focus_position = 1
    except (IndexError, AttributeError):
        # Always set a default focus
        settings_pile.focus_position = 1
    
    # Create main pile without cat art
    main_pile = urwid.Pile([
        ('pack', settings_pile),               # Menu takes only what it needs
        ('weight', 1, urwid.Filler(urwid.Text("")))  # Empty space that expands
    ])
    
    # Update the main widget
    main.original_widget = apply_box_style(
        urwid.Filler(main_pile, valign='top'), 
        title="Settings"
    )

def category_selected(position, callback):
    """Store the selected category position before navigating to submenu"""
    # Position calculation: each item has a divider after it
    # First real item is at position 1 (after initial divider)
    menu_selection_history["settings_menu"] = position * 2 + 1  # Multiply by 2 because of dividers
    callback()  # Call the submenu function

# Helper function to create setting field rows
def create_setting_row(label, widget):
    """Create a row with a label and widget for settings"""
    return urwid.Columns([
        ('fixed', 24, urwid.Text(label)),
        ('weight', 1, widget)
    ])

# Helper function for creating a generic settings submenu
def create_settings_submenu(title, settings_list, back_callback=show_settings):
    """Create a generic settings submenu with the specified settings"""
    
    # Create UI elements for all settings
    settings_widgets = []
    
    # Add all settings rows
    for item in settings_list:
        settings_widgets.append(create_setting_row(item['label'], item['widget']))
        settings_widgets.append(urwid.Divider())
    
    # Create scrollable content area
    settings_pile = urwid.Pile(settings_widgets)
    settings_area = urwid.Filler(settings_pile, valign='top')
    
    # Make the area scrollable if needed
    settings_walker = urwid.SimpleListWalker([settings_area])
    settings_listbox = urwid.ListBox(settings_walker)
    settings_with_scrollbar = urwid.ScrollBar(settings_listbox)
    settings_box = urwid.BoxAdapter(settings_with_scrollbar, 20)  # 20 lines tall
    
    # Back button styled like terminal function - with fixed back handler
    back_button = PlainButton("Back [esc]")
    urwid.connect_signal(back_button, 'click', go_back_one_level)
    
    # Create compact button container to save vertical space
    button_container = urwid.Columns([
        ('weight', 1, urwid.Text("")),
        ('pack', urwid.AttrMap(back_button, None, focus_map="menu_focus")),
        ('weight', 1, urwid.Text(""))
    ])
    
    # Create the settings view with terminal-like layout
    settings_view = urwid.Pile([
        settings_box,
        urwid.Divider(),
        button_container,
        urwid.Divider()
    ])
    
    # Set focus to the settings content
    settings_view.focus_position = 0
    
    # Update the main widget
    main.original_widget = apply_box_style(
        urwid.Filler(settings_view, valign='top', top=0, bottom=0), 
        title=title
    )

# Implementation of each settings category submenu
def show_general_settings():
    """Display General Settings submenu"""
    global current_menu, menu_stack
    
    # Update menu tracking
    if current_menu != "settings_general":
        menu_stack.append(current_menu)
        current_menu = "settings_general"
    
    # Create widgets for each setting
    user_agent = urwid.Edit("", "EVS Email Validator v1.0")
    log_limit = urwid.IntEdit("", 100)
    version = urwid.Text("1.0.0")
    created_at = urwid.Text("2025-03-14")
    last_updated = urwid.Text("2025-03-14")
    
    settings = [
        {"label": "User Agent:", "widget": user_agent},
        {"label": "Log Display Limit:", "widget": log_limit},
        {"label": "Version:", "widget": version},
        {"label": "Created At:", "widget": created_at},
        {"label": "Last Updated:", "widget": last_updated}
    ]
    
    create_settings_submenu("General Settings", settings)

def show_user_settings():
    """Display User Settings submenu"""
    global current_menu, menu_stack
    
    # Update menu tracking
    if current_menu != "settings_user":
        menu_stack.append(current_menu)
        current_menu = "settings_user"
    
    # Create widgets for each setting
    name = urwid.Edit("", "Default User")
    email = urwid.Edit("", "user@example.com")
    active = urwid.CheckBox("", True)
    created_at = urwid.Text("2025-03-14")
    
    settings = [
        {"label": "Name:", "widget": name},
        {"label": "Email:", "widget": email},
        {"label": "Active Status:", "widget": active},
        {"label": "Created At:", "widget": created_at}
    ]
    
    create_settings_submenu("User Settings", settings)

def show_smtp_settings():
    """Display SMTP Settings submenu"""
    global current_menu, menu_stack
    
    # Update menu tracking
    if current_menu != "settings_smtp":
        menu_stack.append(current_menu)
        current_menu = "settings_smtp"
    
    # Create widgets for each setting
    max_retries = urwid.IntEdit("", 3)
    timeout = urwid.IntEdit("", 10)
    retry_delay = urwid.IntEdit("", 2)
    test_sender = urwid.Edit("", "test@example.com")
    hello_cmd = urwid.Edit("", "HELO")
    pool_size = urwid.IntEdit("", 5)
    
    # Port priority checkboxes
    port_25 = urwid.CheckBox("25", True)
    port_587 = urwid.CheckBox("587", True)
    port_465 = urwid.CheckBox("465", True)
    
    settings = [
        {"label": "Max Retries:", "widget": max_retries},
        {"label": "Timeout (seconds):", "widget": timeout},
        {"label": "Retry Delay (seconds):", "widget": retry_delay},
        {"label": "Test Sender Email:", "widget": test_sender},
        {"label": "Hello Command:", "widget": hello_cmd},
        {"label": "Pool Size:", "widget": pool_size},
        {"label": "Priority 1:", "widget": port_25},
        {"label": "Priority 2:", "widget": port_587},
        {"label": "Priority 3:", "widget": port_465}
    ]
    
    create_settings_submenu("SMTP Settings", settings)

def show_rate_limits():
    """Display Rate Limits submenu"""
    global current_menu, menu_stack
    
    # Update menu tracking
    if current_menu != "settings_rate_limits":
        menu_stack.append(current_menu)
        current_menu = "settings_rate_limits"
    
    # Create widgets for each setting
    smtp_vrfy = urwid.IntEdit("", 5)
    smtp_conn = urwid.IntEdit("", 10)
    dns_lookup = urwid.IntEdit("", 20)
    default = urwid.IntEdit("", 10)
    window = urwid.IntEdit("", 60)
    
    settings = [
        {"label": "SMTP VRFY (per window):", "widget": smtp_vrfy},
        {"label": "SMTP Connection (per window):", "widget": smtp_conn},
        {"label": "DNS Lookup (per window):", "widget": dns_lookup},
        {"label": "Default (per window):", "widget": default},
        {"label": "Rate Limit Window (seconds):", "widget": window}
    ]
    
    create_settings_submenu("Rate Limits", settings)

def show_validation_and_confidence():
    """Display Validation Scoring and Confidence Levels side by side"""
    global current_menu, menu_stack
    
    # Update menu tracking
    if current_menu != "settings_validation":
        menu_stack.append(current_menu)
        current_menu = "settings_validation"
    
    # Create widgets for Validation Scoring
    valid_format = urwid.IntEdit("", 20)
    not_disposable = urwid.IntEdit("", 10)
    disposable = urwid.IntEdit("", -10)
    blacklisted = urwid.IntEdit("", -15)
    mx_records = urwid.IntEdit("", 20)
    spf_found = urwid.IntEdit("", 5)
    dkim_found = urwid.IntEdit("", 5)
    smtp_connection = urwid.IntEdit("", 30)
    catch_all = urwid.IntEdit("", -15)
    no_catch_all = urwid.IntEdit("", 15)
    vrfy_confirmed = urwid.IntEdit("", 10)
    imap_available = urwid.IntEdit("", 5)
    pop3_available = urwid.IntEdit("", 5)
    
    # Create widgets for Confidence Levels
    very_high_min = urwid.IntEdit("", 90)
    high_min = urwid.IntEdit("", 70)
    medium_min = urwid.IntEdit("", 50)
    low_min = urwid.IntEdit("", 30)
    very_low_min = urwid.IntEdit("", 0)
    
    # Create left column for Validation Scoring
    validation_settings = [
        urwid.Text(('bold_title', "Validation Scoring")),
        urwid.Divider(),
        create_setting_row("Valid Format Score:", valid_format),
        create_setting_row("Not Disposable Score:", not_disposable),
        create_setting_row("Disposable Score:", disposable),
        create_setting_row("Blacklisted Score:", blacklisted),
        create_setting_row("MX Records Score:", mx_records),
        create_setting_row("SPF Found Score:", spf_found),
        create_setting_row("DKIM Found Score:", dkim_found),
        create_setting_row("SMTP Connection Score:", smtp_connection),
        create_setting_row("Catch All Score:", catch_all),
        create_setting_row("No Catch All Score:", no_catch_all),
        create_setting_row("VRFY Confirmed Score:", vrfy_confirmed),
        create_setting_row("IMAP Available Score:", imap_available),
        create_setting_row("POP3 Available Score:", pop3_available),
    ]
    
    # Create right column for Confidence Levels
    confidence_settings = [
        urwid.Text(('bold_title', "Confidence Levels")),
        urwid.Divider(),
        create_setting_row("Very High (min score):", very_high_min),
        create_setting_row("High (min score):", high_min),
        create_setting_row("Medium (min score):", medium_min),
        create_setting_row("Low (min score):", low_min),
        create_setting_row("Very Low (min score):", very_low_min),
        # Add extra space to align with left column
        urwid.Divider(),
        urwid.Divider(),
        urwid.Divider(),
        urwid.Divider(),
        urwid.Divider(),
        urwid.Divider(),
        urwid.Divider(),
        urwid.Divider(),
    ]
    
    # Create a column widget to place the two sections side by side
    left_pile = urwid.Pile(validation_settings)
    right_pile = urwid.Pile(confidence_settings)
    
    columns = urwid.Columns([
        ('weight', 1, left_pile),
        ('weight', 1, right_pile),
    ])
    
    # Create scrollable area for settings
    settings_walker = urwid.SimpleListWalker([columns])
    settings_listbox = urwid.ListBox(settings_walker)
    settings_with_scrollbar = urwid.ScrollBar(settings_listbox)
    settings_box = urwid.BoxAdapter(settings_with_scrollbar, 20)
    
    # Back button styled like terminal function
    back_button = PlainButton("Back [esc]")
    urwid.connect_signal(back_button, 'click', go_back_one_level)
    
    # Create compact button container to save vertical space
    button_container = urwid.Columns([
        ('weight', 1, urwid.Text("")),
        ('pack', urwid.AttrMap(back_button, None, focus_map="menu_focus")),
        ('weight', 1, urwid.Text(""))
    ])
    
    # Create the settings view with terminal-like layout
    settings_view = urwid.Pile([
        settings_box,
        urwid.Divider(),
        button_container,
        urwid.Divider()
    ])
    
    # Update the main widget
    main.original_widget = apply_box_style(
        urwid.Filler(settings_view, valign='top', top=0, bottom=0), 
        title="Validation & Confidence"
    )

def show_thread_pool_settings():
    """Display Thread Pool Settings submenu"""
    global current_menu, menu_stack
    
    # Update menu tracking
    if current_menu != "settings_thread_pool":
        menu_stack.append(current_menu)
        current_menu = "settings_thread_pool"
    
    # Add implementation for Thread Pool Settings
    max_workers = urwid.IntEdit("", 10)
    conn_timeout = urwid.IntEdit("", 15)
    idle_timeout = urwid.IntEdit("", 60)
    
    settings = [
        {"label": "Max Worker Threads:", "widget": max_workers},
        {"label": "Connection Timeout (s):", "widget": conn_timeout},
        {"label": "Thread Idle Timeout (s):", "widget": idle_timeout}
    ]
    
    create_settings_submenu("Thread Pool Settings", settings)

def show_cache_settings():
    """Display Cache Settings submenu"""
    global current_menu, menu_stack
    
    # Update menu tracking
    if current_menu != "settings_cache":
        menu_stack.append(current_menu)
        current_menu = "settings_cache"
    
    # Add implementation for Cache Settings
    mx_max_size = urwid.IntEdit("", 1000)
    mx_ttl = urwid.IntEdit("", 3600)
    mx_cleanup = urwid.IntEdit("", 60)
    
    ttl_max_size = urwid.IntEdit("", 128)
    ttl_ttl = urwid.IntEdit("", 600)
    ttl_cleanup = urwid.IntEdit("", 60)
    
    settings = [
        {"label": "Max Size:", "widget": mx_max_size},
        {"label": "TTL (seconds):", "widget": mx_ttl},
        {"label": "Cleanup Interval (s):", "widget": mx_cleanup},
        {"label": "Max Size:", "widget": ttl_max_size},
        {"label": "TTL (seconds):", "widget": ttl_ttl},
        {"label": "Cleanup Interval (s):", "widget": ttl_cleanup}
    ]
    
    create_settings_submenu("Cache Settings", settings)

def show_dns_settings():
    """Display DNS Settings submenu"""
    global current_menu, menu_stack
    
    # Update menu tracking
    if current_menu != "settings_dns":
        menu_stack.append(current_menu)
        current_menu = "settings_dns"
    
    # Add implementation for DNS Settings
    timeout = urwid.IntEdit("", 10)
    nameservers = urwid.Edit("", "8.8.8.8, 1.1.1.1")
    a_record_fallback = urwid.CheckBox("", True)
    dkim_selector = urwid.Edit("", "default")
    
    settings = [
        {"label": "Timeout (seconds):", "widget": timeout},
        {"label": "Nameservers:", "widget": nameservers},
        {"label": "A Record Fallback:", "widget": a_record_fallback},
        {"label": "DKIM Selector:", "widget": dkim_selector}
    ]
    
    create_settings_submenu("DNS Settings", settings)

def show_protocol_settings():
    """Display Protocol Settings submenu"""
    global current_menu, menu_stack
    
    # Update menu tracking
    if current_menu != "settings_protocol":
        menu_stack.append(current_menu)
        current_menu = "settings_protocol"
    
    # Add implementation for Protocol Settings
    imap_port = urwid.IntEdit("", 993)
    imap_timeout = urwid.IntEdit("", 5)
    
    pop3_port = urwid.IntEdit("", 995)
    pop3_timeout = urwid.IntEdit("", 5)
    
    settings = [
        {"label": "Port:", "widget": imap_port},
        {"label": "Timeout (seconds):", "widget": imap_timeout},
        {"label": "Port:", "widget": pop3_port},
        {"label": "Timeout (seconds):", "widget": pop3_timeout}
    ]
    
    create_settings_submenu("Protocol Settings", settings)

def show_security_settings():
    """Display Security Settings submenu"""
    global current_menu, menu_stack
    
    # Update menu tracking
    if current_menu != "settings_security":
        menu_stack.append(current_menu)
        current_menu = "settings_security"
    
    # Add implementation for Security Settings
    blacklist_file = urwid.Edit("", "blacklist.txt")
    disposable_file = urwid.Edit("", "disposable.txt")
    spf_verification = urwid.CheckBox("", True)
    dkim_verification = urwid.CheckBox("", True)
    server_policy = urwid.CheckBox("", True)
    
    settings = [
        {"label": "Blacklisted Domains File:", "widget": blacklist_file},
        {"label": "Disposable Domains File:", "widget": disposable_file},
        {"label": "SPF Verification:", "widget": spf_verification},
        {"label": "DKIM Verification:", "widget": dkim_verification},
        {"label": "Server Policy Checks:", "widget": server_policy}
    ]
    
    create_settings_submenu("Security Settings", settings)

def show_logging_fields():
    """Display Logging Fields submenu"""
    global current_menu, menu_stack
    
    # Update menu tracking
    if current_menu != "settings_logging":
        menu_stack.append(current_menu)
        current_menu = "settings_logging"
    
    # Add implementation for Logging Fields
    core_fields = urwid.CheckBox("", True)
    security_fields = urwid.CheckBox("", True)
    technical_fields = urwid.CheckBox("", True)
    protocol_fields = urwid.CheckBox("", True)
    metadata_fields = urwid.CheckBox("", True)
    
    settings = [
        {"label": "Core Fields:", "widget": core_fields},
        {"label": "Security Fields:", "widget": security_fields},
        {"label": "Technical Fields:", "widget": technical_fields},
        {"label": "Protocol Fields:", "widget": protocol_fields},
        {"label": "Metadata Fields:", "widget": metadata_fields}
    ]
    
    create_settings_submenu("Logging Fields", settings)

def start_text():
    art = """
 ██████████ █████   █████  █████████ 
░░███░░░░░█░░███   ░░███  ███░░░░░███
 ░███  █ ░  ░███    ░███ ░███    ░░░ 
 ░██████    ░███    ░███ ░░█████████ 
 ░███░░█    ░░███   ███   ░░░░░░░░███
 ░███ ░   █  ░░░█████░    ███    ░███
 ██████████    ░░███     ░░█████████ 
░░░░░░░░░░      ░░░       ░░░░░░░░░  
"""
    # Split into lines, center each line, then rejoin
    lines = art.split("\n")
    # Find the maximum line width to ensure proper centering
    max_width = max(len(line) for line in lines)
    centered_lines = [line.center(max_width) for line in lines]
    return "\n".join(centered_lines)

# Create the menu with a LineBox around it
main_menu = menu(start_text(), choices)
boxed_menu = urwid.LineBox(main_menu, title="Email Verification Script")
main = urwid.Padding(boxed_menu, left=1, right=1)

top = urwid.Overlay(
    main,
    urwid.SolidFill("\N{MEDIUM SHADE}"),
    align=urwid.CENTER,
    width=(urwid.RELATIVE, 80),
    valign=urwid.MIDDLE,
    height=(urwid.RELATIVE, 30),
    min_width=80,
    min_height=30,
)

# Add this helper function
def go_back_one_level(button=None):
    """Navigate to the previous menu level based on menu stack"""
    global current_menu, menu_stack
    
    if menu_stack:
        # Pop the previous menu and navigate to it
        prev_menu = menu_stack.pop()
        current_menu = prev_menu
        
        # Call the appropriate function based on menu type
        if prev_menu == "main":
            go_back_to_main()
        elif prev_menu == "settings":
            show_settings()
        elif prev_menu == "batch":
            show_batch_operations()
        elif prev_menu == "validation_records":
            show_validation_records()
        elif prev_menu == "custom_filter":
            show_custom_filtered_records()
        elif prev_menu == "file_browser":
            show_file_browser()
        elif prev_menu == "batch_history":
            show_batch_history()
        elif prev_menu == "audit_log":
            show_audit_log()
        elif prev_menu == "help":
            menu_help()
        elif prev_menu == "terminal":
            terminal_function()
        # Add handlers for ALL other menu types here
        else:
            # Fallback to main menu if handler not found
            logger.warning(f"No handler found for menu: {prev_menu}, going to main menu")
            current_menu = "main"
            go_back_to_main()
    else:
        # Stack is empty, go to main menu
        current_menu = "main"
        go_back_to_main()

def global_keypress(key):
    global current_menu, menu_stack
    
    if key == 'esc':  # When ESC is pressed anywhere in the app
        if current_menu == "main":
            # Already at main menu, do nothing
            return True
        elif current_menu == "batch_progress":
            # Find the cancel button and trigger its click event
            # This will properly call cancel_batch()
            loop = get_main_loop()
            if loop and hasattr(loop.widget, 'original_widget'):
                # Get the button row from the progress pile (at index 13)
                try:
                    pile = loop.widget.original_widget.original_widget.original_widget.body
                    button_row = pile[13][0]  # Access the button row
                    cancel_button = button_row.contents[1][0]  # Get the cancel button
                    cancel_button._emit('click')  # Simulate button click
                    return True
                except (IndexError, AttributeError):
                    logger.error("Failed to find cancel button when ESC pressed")
        else:
            # Standard navigation for other screens
            go_back_one_level()
            return True
    return False

def show_export():
    """Display Import/Export menu"""
    global current_menu, menu_stack
    
    # Update menu tracking
    if current_menu != "import_export":
        menu_stack.append(current_menu)
        current_menu = "import_export"
    
    # Create export buttons
    export_date_btn = PlainButton("Export by Date Range")
    export_batch_btn = PlainButton("Export by Batch")
    export_domain_btn = PlainButton("Export by Domain")
    export_confidence_btn = PlainButton("Export by Confidence Level")
    export_all_btn = PlainButton("Export All Records")
    export_meta_btn = PlainButton("Export by Field Categories")
    
    # Connect signals
    urwid.connect_signal(export_date_btn, 'click', lambda button: show_export_date_range())
    urwid.connect_signal(export_batch_btn, 'click', lambda button: show_export_batch())
    urwid.connect_signal(export_domain_btn, 'click', lambda button: show_export_domain())
    urwid.connect_signal(export_confidence_btn, 'click', lambda button: show_export_confidence())
    urwid.connect_signal(export_all_btn, 'click', lambda button: show_export_all())
    urwid.connect_signal(export_meta_btn, 'click', lambda button: show_export_meta())
    
    # Style buttons
    export_date_btn = urwid.AttrMap(export_date_btn, None, focus_map="menu_focus")
    export_batch_btn = urwid.AttrMap(export_batch_btn, None, focus_map="menu_focus")
    export_domain_btn = urwid.AttrMap(export_domain_btn, None, focus_map="menu_focus")
    export_confidence_btn = urwid.AttrMap(export_confidence_btn, None, focus_map="menu_focus")
    export_all_btn = urwid.AttrMap(export_all_btn, None, focus_map="menu_focus")
    export_meta_btn = urwid.AttrMap(export_meta_btn, None, focus_map="menu_focus")
    
    # Calculate width for consistent layout
    max_length = max(len("Export by Date Range"), len("Export by Batch"), len("Export by Domain"),
                     len("Export by Confidence Level"), len("Export All Records"), 
                     len("Export by Field Categories"))
    menu_width = max_length + 4  # Add padding
    
    # Create centered button containers
    export_date_container = urwid.Columns([
        ('weight', 1, urwid.Text("")),
        ('fixed', menu_width, export_date_btn),
        ('weight', 1, urwid.Text(""))
    ])
    
    export_batch_container = urwid.Columns([
        ('weight', 1, urwid.Text("")),
        ('fixed', menu_width, export_batch_btn),
        ('weight', 1, urwid.Text(""))
    ])
    
    export_domain_container = urwid.Columns([
        ('weight', 1, urwid.Text("")),
        ('fixed', menu_width, export_domain_btn),
        ('weight', 1, urwid.Text(""))
    ])
    
    export_confidence_container = urwid.Columns([
        ('weight', 1, urwid.Text("")),
        ('fixed', menu_width, export_confidence_btn),
        ('weight', 1, urwid.Text(""))
    ])
    
    export_all_container = urwid.Columns([
        ('weight', 1, urwid.Text("")),
        ('fixed', menu_width, export_all_btn),
        ('weight', 1, urwid.Text(""))
    ])
    
    export_meta_container = urwid.Columns([
        ('weight', 1, urwid.Text("")),
        ('fixed', menu_width, export_meta_btn),
        ('weight', 1, urwid.Text(""))
    ])
    
    # Back button
    back_button = PlainButton("Back [esc]")
    urwid.connect_signal(back_button, 'click', go_back_one_level)
    
    back_container = urwid.Columns([
        ('weight', 1, urwid.Text("")),
        ('fixed', menu_width, urwid.AttrMap(back_button, None, focus_map="menu_focus")),
        ('weight', 1, urwid.Text(""))
    ])
    
    # Create menu layout
    menu_items = [
        urwid.Divider(),
        urwid.Text("Select export option:", align='center'),
        urwid.Divider(),
        export_date_container,
        urwid.Divider(),
        export_batch_container,
        urwid.Divider(),
        export_domain_container,
        urwid.Divider(),
        export_confidence_container,
        urwid.Divider(),
        export_all_container,
        urwid.Divider(),
        export_meta_container,
        urwid.Divider(),
        back_container
    ]
    
    menu_pile = urwid.Pile(menu_items)
    
    # Update main widget
    main.original_widget = apply_box_style(
        urwid.Filler(menu_pile, valign='top'),
        title="Export Options"
    )

def show_export_date_range():
    """Show date range export options"""
    global current_menu, menu_stack
    
    if current_menu != "export_date":
        menu_stack.append(current_menu)
        current_menu = "export_date"
    
    # Create date input fields
    from datetime import datetime
    
    start_edit = urwid.Edit("", "")
    end_edit = urwid.Edit("", "")
    
    # Format options
    format_group = []
    csv_radio = urwid.RadioButton(format_group, "CSV", True)
    json_radio = urwid.RadioButton(format_group, "JSON")
    
    # Create export button
    export_button = PlainButton("Export")
    
    def on_export_clicked(button):
        try:
            # Parse date inputs
            start_date = None
            end_date = None
            
            if start_edit.edit_text.strip():
                start_date = datetime.strptime(start_edit.edit_text.strip(), "%Y-%m-%d")
                start_date = start_date.replace(hour=0, minute=0, second=0)  # Start of day
            
            if end_edit.edit_text.strip():
                end_date = datetime.strptime(end_edit.edit_text.strip(), "%Y-%m-%d")
                end_date = end_date.replace(hour=23, minute=59, second=59)  # End of day
            
            # Determine format
            format_type = "csv" if csv_radio.state else "json"
            
            # Call export function
            result = Core.export_date_range(start_date, end_date, format_type)
            
            # Show result
            if result['success']:
                show_success_dialog(f"Export successful. {result['count']} records exported to {result['file_path']}",
                                   show_export)
            else:
                show_error_dialog(result['message'], show_export_date_range)
                
        except ValueError:
            # Show error for invalid date format
            show_error_dialog("Invalid date format. Please use YYYY-MM-DD format.", show_export_date_range)
    
    urwid.connect_signal(export_button, 'click', on_export_clicked)
    
    # Create cancel button
    cancel_button = PlainButton("Cancel [esc]")
    urwid.connect_signal(cancel_button, 'click', go_back_one_level)
    
    # Layout
    pile = urwid.Pile([
        urwid.Text("Export by Date Range"),
        urwid.Divider(),
        urwid.Text("Start date (YYYY-MM-DD, leave empty for no start limit):"),
        urwid.AttrMap(start_edit, "edit_unfocused", "edit_focused"),
        urwid.Divider(),
        urwid.Text("End date (YYYY-MM-DD, leave empty for no end limit):"),
        urwid.AttrMap(end_edit, "edit_unfocused", "edit_focused"),
        urwid.Divider(),
        urwid.Text("Export format:"),
        csv_radio,
        json_radio,
        urwid.Divider(),
        urwid.Columns([
            ('weight', 1, urwid.Text("")),
            ('pack', urwid.AttrMap(export_button, None, focus_map="menu_focus")),
            ('fixed', 3, urwid.Text(" ")),
            ('pack', urwid.AttrMap(cancel_button, None, focus_map="menu_focus")),
            ('weight', 1, urwid.Text(""))
        ])
    ])
    
    # Update main widget
    main.original_widget = apply_box_style(
        urwid.Filler(pile, valign='top'),
        title="Export by Date Range"
    )

def show_export_batch():
    """Show batch export options"""
    global current_menu, menu_stack
    
    if current_menu != "export_batch":
        menu_stack.append(current_menu)
        current_menu = "export_batch"
    
    # Get list of batches
    from config import config
    cfg = config()
    batches = cfg.batch_info.list_batches()
    
    if not batches:
        show_error_dialog("No batches found in database.", show_export)
        return
    
    # Create batch selector
    batch_items = []
    for batch in batches:
        batch_id = batch.get('id', 'N/A')
        batch_name = batch.get('name', f'Batch {batch_id}')
        option_text = f"ID: {batch_id} - {batch_name}"
        batch_items.append(option_text)
    
    # Create batch selection buttons
    batch_buttons = []
    for i, txt in enumerate(batch_items):
        btn = urwid.AttrMap(
            urwid.Button(txt, on_press=lambda button, id=i+1: select_batch(id)), 
            None, "menu_focus"
        )
        batch_buttons.append(btn)
    
    # Create scrollable list box
    batch_walker = urwid.SimpleListWalker(batch_buttons)
    batch_listbox = urwid.ListBox(batch_walker)
    
    # Use BoxAdapter to limit the height
    batch_selector = urwid.BoxAdapter(batch_listbox, 10)
    
    # Selected batch display
    selected_batch_text = urwid.Text("No batch selected")
    
    # Format options
    format_group = []
    csv_radio = urwid.RadioButton(format_group, "CSV", True)
    json_radio = urwid.RadioButton(format_group, "JSON")
    
    # Selected batch ID storage
    selected_batch_id = [None]  # Use list for mutability
    
    def select_batch(batch_id):
        selected_batch_id[0] = batch_id
        # Find batch name
        batch_name = "Unknown"
        for batch in batches:
            if batch.get('id') == batch_id:
                batch_name = batch.get('name', f'Batch {batch_id}')
                break
        selected_batch_text.set_text(f"Selected: ID: {batch_id} - {batch_name}")
    
    # Create export button
    export_button = PlainButton("Export")
    
    def on_export_clicked(button):
        if selected_batch_id[0] is None:
            show_error_dialog("Please select a batch first.", show_export_batch)
            return
        
        # Determine format
        format_type = "csv" if csv_radio.state else "json"
        
        # Call export function
        result = Core.export_batch(selected_batch_id[0], format_type)
        
        # Show result
        if result['success']:
            show_success_dialog(f"Export successful. {result['count']} records exported to {result['file_path']}",
                               show_export)
        else:
            show_error_dialog(result['message'], show_export_batch)
    
    urwid.connect_signal(export_button, 'click', on_export_clicked)
    
    # Create cancel button
    cancel_button = PlainButton("Cancel [esc]")
    urwid.connect_signal(cancel_button, 'click', go_back_one_level)
    
    # Layout
    pile = urwid.Pile([
        urwid.Text("Export by Batch"),
        urwid.Divider(),
        batch_selector,
        urwid.Divider(),
        selected_batch_text,
        urwid.Divider(),
        urwid.Text("Export format:"),
        csv_radio,
        json_radio,
        urwid.Divider(),
        urwid.Columns([
            ('weight', 1, urwid.Text("")),
            ('pack', urwid.AttrMap(export_button, None, focus_map="menu_focus")),
            ('fixed', 3, urwid.Text(" ")),
            ('pack', urwid.AttrMap(cancel_button, None, focus_map="menu_focus")),
            ('weight', 1, urwid.Text(""))
        ])
    ])
    
    # Update main widget
    main.original_widget = apply_box_style(
        urwid.Filler(pile, valign='top'),
        title="Export by Batch"
    )

def show_export_domain():
    """Show domain export options"""
    global current_menu, menu_stack
    
    if current_menu != "export_domain":
        menu_stack.append(current_menu)
        current_menu = "export_domain"
    
    # Domain input field
    domain_edit = urwid.Edit("", "")
    
    # Format options
    format_group = []
    csv_radio = urwid.RadioButton(format_group, "CSV", True)
    json_radio = urwid.RadioButton(format_group, "JSON")
    
    # Create export button
    export_button = PlainButton("Export")
    
    def on_export_clicked(button):
        domains = domain_edit.edit_text.strip()
        if not domains:
            show_error_dialog("Please enter at least one domain.", show_export_domain)
            return
        
        # Determine format
        format_type = "csv" if csv_radio.state else "json"
        
        # Call export function
        result = Core.export_domain(domains, format_type)
        
        # Show result
        if result['success']:
            show_success_dialog(f"Export successful. {result['count']} records exported to {result['file_path']}",
                               show_export)
        else:
            show_error_dialog(result['message'], show_export_domain)
    
    urwid.connect_signal(export_button, 'click', on_export_clicked)
    
    # Create cancel button
    cancel_button = PlainButton("Cancel [esc]")
    urwid.connect_signal(cancel_button, 'click', go_back_one_level)
    
    # Layout
    pile = urwid.Pile([
        urwid.Text("Export by Domain"),
        urwid.Divider(),
        urwid.Text("Enter domains to export (comma-separated, e.g. gmail.com,yahoo.com):"),
        urwid.AttrMap(domain_edit, "edit_unfocused", "edit_focused"),
        urwid.Divider(),
        urwid.Text("Export format:"),
        csv_radio,
        json_radio,
        urwid.Divider(),
        urwid.Columns([
            ('weight', 1, urwid.Text("")),
            ('pack', urwid.AttrMap(export_button, None, focus_map="menu_focus")),
            ('fixed', 3, urwid.Text(" ")),
            ('pack', urwid.AttrMap(cancel_button, None, focus_map="menu_focus")),
            ('weight', 1, urwid.Text(""))
        ])
    ])
    
    # Update main widget
    main.original_widget = apply_box_style(
        urwid.Filler(pile, valign='top'),
        title="Export by Domain"
    )

def show_export_confidence():
    """Show confidence level export options"""
    global current_menu, menu_stack
    
    if current_menu != "export_confidence":
        menu_stack.append(current_menu)
        current_menu = "export_confidence"
    
    # Confidence level checkboxes
    very_low = urwid.CheckBox("Very Low (0-20)", False)
    low = urwid.CheckBox("Low (21-40)", False)
    medium = urwid.CheckBox("Medium (41-60)", False)
    high = urwid.CheckBox("High (61-80)", False)
    very_high = urwid.CheckBox("Very High (81-100)", False)
    
    # Format options
    format_group = []
    csv_radio = urwid.RadioButton(format_group, "CSV", True)
    json_radio = urwid.RadioButton(format_group, "JSON")
    
    # Create export button
    export_button = PlainButton("Export")
    
    def on_export_clicked(button):
        # Collect selected confidence levels
        confidence_levels = []
        if very_low.state:
            confidence_levels.append("Very Low")
        if low.state:
            confidence_levels.append("Low")
        if medium.state:
            confidence_levels.append("Medium")
        if high.state:
            confidence_levels.append("High")
        if very_high.state:
            confidence_levels.append("Very High")
        
        if not confidence_levels:
            show_error_dialog("Please select at least one confidence level.", show_export_confidence)
            return
        
        # Determine format
        format_type = "csv" if csv_radio.state else "json"
        
        # Call export function
        result = Core.export_confidence(confidence_levels, format_type)
        
        # Show result
        if result['success']:
            show_success_dialog(f"Export successful. {result['count']} records exported to {result['file_path']}",
                               show_export)
        else:
            show_error_dialog(result['message'], show_export_confidence)
    
    urwid.connect_signal(export_button, 'click', on_export_clicked)
    
    # Create cancel button
    cancel_button = PlainButton("Cancel [esc]")
    urwid.connect_signal(cancel_button, 'click', go_back_one_level)
    
    # Layout
    pile = urwid.Pile([
        urwid.Text("Export by Confidence Level"),
        urwid.Divider(),
        urwid.Text("Select confidence levels to export:"),
        very_low,
        low,
        medium,
        high,
        very_high,
        urwid.Divider(),
        urwid.Text("Export format:"),
        csv_radio,
        json_radio,
        urwid.Divider(),
        urwid.Columns([
            ('weight', 1, urwid.Text("")),
            ('pack', urwid.AttrMap(export_button, None, focus_map="menu_focus")),
            ('fixed', 3, urwid.Text(" ")),
            ('pack', urwid.AttrMap(cancel_button, None, focus_map="menu_focus")),
            ('weight', 1, urwid.Text(""))
        ])
    ])
    
    # Update main widget
    main.original_widget = apply_box_style(
        urwid.Filler(pile, valign='top'),
        title="Export by Confidence Level"
    )

def show_export_all():
    """Show export all records options"""
    global current_menu, menu_stack
    
    if current_menu != "export_all":
        menu_stack.append(current_menu)
        current_menu = "export_all"
    
    # Format options
    format_group = []
    csv_radio = urwid.RadioButton(format_group, "CSV", True)
    json_radio = urwid.RadioButton(format_group, "JSON")
    
    # Get record count
    from config import config
    cfg = config()
    record_count = 0
    try:
        with cfg.connect() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM email_validation_records")
            result = cursor.fetchone()
            record_count = result[0] if result else 0
    except Exception as e:
        logger.error(f"Error counting records: {e}")
    
    # Create export button
    export_button = PlainButton("Export All Records")
    
    def on_export_clicked(button):
        # Determine format
        format_type = "csv" if csv_radio.state else "json"
        
        # Call export function
        result = Core.export_all(format_type)
        
        # Show result
        if result['success']:
            show_success_dialog(f"Export successful. {result['count']} records exported to {result['file_path']}",
                               show_export)
        else:
            show_error_dialog(result['message'], show_export_all)
    
    urwid.connect_signal(export_button, 'click', on_export_clicked)
    
    # Create cancel button
    cancel_button = PlainButton("Cancel [esc]")
    urwid.connect_signal(cancel_button, 'click', go_back_one_level)
    
    # Layout
    pile = urwid.Pile([
        urwid.Text("Export All Records"),
        urwid.Divider(),
        urwid.Text(f"This will export all {record_count} records in the database."),
        urwid.Divider(),
        urwid.Text("Export format:"),
        csv_radio,
        json_radio,
        urwid.Divider(),
        urwid.Columns([
            ('weight', 1, urwid.Text("")),
            ('pack', urwid.AttrMap(export_button, None, focus_map="menu_focus")),
            ('fixed', 3, urwid.Text(" ")),
            ('pack', urwid.AttrMap(cancel_button, None, focus_map="menu_focus")),
            ('weight', 1, urwid.Text(""))
        ])
    ])
    
    # Update main widget
    main.original_widget = apply_box_style(
        urwid.Filler(pile, valign='top'),
        title="Export All Records"
    )

def show_export_meta():
    """Show metadata category export options"""
    global current_menu, menu_stack
    
    if current_menu != "export_meta":
        menu_stack.append(current_menu)
        current_menu = "export_meta"
    
    # Category checkboxes
    metadata = urwid.CheckBox("Metadata", False)
    core = urwid.CheckBox("Core", False)
    security = urwid.CheckBox("Security", False)
    technical = urwid.CheckBox("Technical", False)
    protocol = urwid.CheckBox("Protocol", False)
    
    # Format options
    format_group = []
    csv_radio = urwid.RadioButton(format_group, "CSV", True)
    json_radio = urwid.RadioButton(format_group, "JSON")
    
    # Create export button
    export_button = PlainButton("Export")
    
    def on_export_clicked(button):
        # Collect selected categories
        categories = []
        if metadata.state:
            categories.append("Metadata")
        if core.state:
            categories.append("Core")
        if security.state:
            categories.append("Security")
        if technical.state:
            categories.append("Technical")
        if protocol.state:
            categories.append("Protocol")
        
        if not categories:
            show_error_dialog("Please select at least one category.", show_export_meta)
            return
        
        # Determine format
        format_type = "csv" if csv_radio.state else "json"
        
        # Call export function
        result = Core.export_meta(categories, format_type)
        
        # Show result
        if result['success']:
            show_success_dialog(f"Export successful. {result['count']} records exported to {result['file_path']}",
                               show_export)
        else:
            show_error_dialog(result['message'], show_export_meta)
    
    urwid.connect_signal(export_button, 'click', on_export_clicked)
    
    # Create cancel button
    cancel_button = PlainButton("Cancel [esc]")
    urwid.connect_signal(cancel_button, 'click', go_back_one_level)
    
    # Layout
    pile = urwid.Pile([
        urwid.Text("Export by Field Categories"),
        urwid.Divider(),
        urwid.Text("Select field categories to include:"),
        metadata,
        core,
        security,
        technical,
        protocol,
        urwid.Divider(),
        urwid.Text("Export format:"),
        csv_radio,
        json_radio,
        urwid.Divider(),
        urwid.Columns([
            ('weight', 1, urwid.Text("")),
            ('pack', urwid.AttrMap(export_button, None, focus_map="menu_focus")),
            ('fixed', 3, urwid.Text(" ")),
            ('pack', urwid.AttrMap(cancel_button, None, focus_map="menu_focus")),
            ('weight', 1, urwid.Text(""))
        ])
    ])
    
    # Update main widget
    main.original_widget = apply_box_style(
        urwid.Filler(pile, valign='top'),
        title="Export by Field Categories"
    )

# Add success dialog function similar to error dialog
def show_success_dialog(message, callback):
    """Show a success dialog with a message and OK button"""
    # Create success message
    success_text = urwid.Text(message, align='center')
    
    # OK button
    ok_button = PlainButton("OK")
    urwid.connect_signal(ok_button, 'click', lambda button: callback())
    
    # Create button container
    button_container = urwid.Columns([
        ('weight', 1, urwid.Text("")),
        ('pack', urwid.AttrMap(ok_button, None, focus_map="menu_focus")),
        ('weight', 1, urwid.Text(""))
    ])
    
    # Create success dialog
    success_pile = urwid.Pile([
        urwid.Divider(),
        success_text,
        urwid.Divider(),
        button_container,
        urwid.Divider()
    ])
    
    # Update main widget
    main.original_widget = apply_box_style(
        urwid.Filler(success_pile, valign='middle'),
        title="Success"
    )

def show_batch_operations():
    """Display Batch operations menu"""
    global current_menu, menu_stack
    
    # Update menu tracking
    if current_menu != "batch":
        menu_stack.append(current_menu)
        current_menu = "batch"
    
    # Create batch operation buttons
    new_batch_btn = PlainButton("New Batch Validation")
    view_batches_btn = PlainButton("View Batch History")
    
    # Connect signals
    urwid.connect_signal(new_batch_btn, 'click', lambda button: show_file_browser())
    urwid.connect_signal(view_batches_btn, 'click', lambda button: show_batch_history())
    
    # Style buttons
    new_batch_btn = urwid.AttrMap(new_batch_btn, None, focus_map="menu_focus")
    view_batches_btn = urwid.AttrMap(view_batches_btn, None, focus_map="menu_focus")
    
    # Calculate width for consistent layout
    max_length = max(len("New Batch Validation"), len("View Batch History"))
    menu_width = max_length + 4  # Add padding
    
    # Create centered button containers
    new_batch_container = urwid.Columns([
        ('weight', 1, urwid.Text("")),
        ('fixed', menu_width, new_batch_btn),
        ('weight', 1, urwid.Text(""))
    ])
    
    view_batches_container = urwid.Columns([
        ('weight', 1, urwid.Text("")),
        ('fixed', menu_width, view_batches_btn),
        ('weight', 1, urwid.Text(""))
    ])
    
    # Add back button
    back_button = PlainButton("Back [esc]")
    urwid.connect_signal(back_button, 'click', go_back_one_level)
    
    back_container = urwid.Columns([
        ('weight', 1, urwid.Text("")),
        ('fixed', menu_width, urwid.AttrMap(back_button, None, focus_map="menu_focus")),
        ('weight', 1, urwid.Text(""))
    ])
    
    # Create batch menu layout
    menu_items = [
        urwid.Divider(),
        urwid.Text("Select an option:", align='center'),
        urwid.Divider(),
        new_batch_container,
        urwid.Divider(),
        view_batches_container,
        urwid.Divider(),
        back_container
    ]
    
    menu_pile = urwid.Pile(menu_items)
    
    # Update main widget
    main.original_widget = apply_box_style(
        urwid.Filler(menu_pile, valign='top'),
        title="Batch Email Validation"
    )

def show_file_browser():
    """Display file browser for selecting email list files"""
    global current_menu, menu_stack
    
    if current_menu != "file_browser":
        menu_stack.append(current_menu)
        current_menu = "file_browser"
    
    # Get current working directory
    cwd = os.getcwd()
    
    def get_dir_contents(path):
        """Get sorted directory contents (dirs first, then files)"""
        try:
            dirs = []
            files = []
            
            for item in os.listdir(path):
                # Skip hidden files
                if item.startswith('.'):
                    continue
                    
                full_path = os.path.join(path, item)
                if os.path.isdir(full_path):
                    dirs.append(item)
                elif os.path.isfile(full_path) and (item.endswith('.txt') or 
                                                  item.endswith('.csv') or 
                                                  item.endswith('.list')):
                    files.append(item)
            
            # Sort alphabetically
            dirs.sort()
            files.sort()
            
            # Add parent directory option if not at root
            contents = []
            if os.path.dirname(path) != path:  # Not at root
                contents.append("..")
                
            # Combine directories and files
            contents.extend(dirs)
            contents.extend(files)
            return contents
        except Exception as e:
            logger.error(f"Error reading directory {path}: {e}")
            return [".."]  # At least allow going back
    
    # Initialize with current directory contents
    dir_contents = get_dir_contents(cwd)
    current_dir = cwd
    
    def update_browser(new_path):
        """Update browser with new directory contents"""
        nonlocal current_dir, dir_contents
        
        if not os.path.exists(new_path):
            return
            
        if os.path.isdir(new_path):
            # Change to new directory
            current_dir = new_path
            dir_contents = get_dir_contents(new_path)
            
            # Clear and rebuild the list walker
            del browser_walker[:]
            
            # Add directory indicator and path
            browser_walker.append(urwid.Text(f"Directory: {current_dir}"))
            browser_walker.append(urwid.Divider())
            
            # Add all items
            for item in dir_contents:
                full_path = os.path.join(current_dir, item)
                
                # Show directories with a trailing slash
                display_name = item
                if os.path.isdir(full_path) and not item == "..":
                    display_name = item + "/"
                
                # Create button for each item
                btn = PlainButton(display_name)
                urwid.connect_signal(btn, 'click', 
                                   lambda button, p=full_path, i=item: item_selected(p, i))
                
                # Add to browser list
                browser_walker.append(urwid.AttrMap(btn, None, focus_map="menu_focus"))
            
            # Set focus to first item
            if len(browser_walker) > 2:  # Skip header and divider
                browser_listbox.focus_position = 2
    
    def item_selected(path, name):
        """Handle selection of a directory or file"""
        if os.path.isdir(path):
            # If directory, navigate into it
            update_browser(path)
        else:
            # If file, proceed to batch setup
            show_batch_setup(path)
    
    # Create initial walker and listbox
    browser_walker = urwid.SimpleListWalker([
        urwid.Text(f"Directory: {current_dir}"),
        urwid.Divider()
    ])
    
    # Add initial directory contents
    for item in dir_contents:
        full_path = os.path.join(current_dir, item)
        
        # Show directories with a trailing slash
        display_name = item
        if os.path.isdir(full_path) and not item == "..":
            display_name = item + "/"
        
        # Create button for each item
        btn = PlainButton(display_name)
        urwid.connect_signal(btn, 'click', 
                           lambda button, p=full_path, i=item: item_selected(p, i))
        
        # Add to browser list
        browser_walker.append(urwid.AttrMap(btn, None, focus_map="menu_focus"))
    
    browser_listbox = urwid.ListBox(browser_walker)
    browser_with_scrollbar = urwid.ScrollBar(browser_listbox)
    browser_box = urwid.BoxAdapter(browser_with_scrollbar, 25)
    
    # Add back button
    back_button = PlainButton("Back [esc]")
    urwid.connect_signal(back_button, 'click', go_back_one_level)
    
    # Create button container
    button_container = urwid.Columns([
        ('weight', 1, urwid.Text("")),
        ('pack', urwid.AttrMap(back_button, None, focus_map="menu_focus")),
        ('weight', 1, urwid.Text(""))
    ])
    
    # Create the file browser view
    browser_view = urwid.Pile([
        browser_box,
        urwid.Divider(),
        button_container,
        urwid.Divider()
    ])
    
    # Update the main widget
    main.original_widget = apply_box_style(
        urwid.Filler(browser_view, valign='top', top=0, bottom=0),
        title="Select Email List File"
    )

def show_batch_setup(file_path):
    """Display batch setup screen with file info and options"""
    global current_menu, menu_stack
    
    if current_menu != "batch_setup":
        menu_stack.append(current_menu)
        current_menu = "batch_setup"
    
    # Count lines in the file and validate format
    email_count = 0
    valid_format = True
    valid_emails = []
    invalid_emails = []  # List to store tuples of (line_number, invalid_email)
    
    try:
        with open(file_path, 'r') as f:
            for i, line in enumerate(f, 1):  # Start line count from 1
                email = line.strip()
                if email:
                    email_count += 1
                    # Check email format for all lines
                    if Core.EMAIL_PATTERN.match(email):
                        valid_emails.append(email)
                    else:
                        valid_format = False
                        # Store the line number and invalid email
                        invalid_emails.append((i, email))
        
        # Get 3 random sample emails if we have enough valid emails
        sample_emails = []
        if valid_emails:
            import random
            # Take up to 3 random emails, or all if fewer than 3
            sample_count = min(3, len(valid_emails))
            sample_emails = random.sample(valid_emails, sample_count)
            
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {e}")
        # Show error and return to file browser
        show_error_dialog(f"Error reading file: {str(e)}", show_file_browser)
        return
    
    if email_count == 0:
        show_error_dialog("The selected file is empty or contains no valid emails.", 
                         show_file_browser)
        return
    
    # Create batch name from filename without extension + batch number
    filename_without_ext = os.path.splitext(os.path.basename(file_path))[0]

    # Get next batch ID
    next_batch_id = 1  # Default value
    try:
        from config import config
        cfg = config()
        with cfg.connect() as conn:
            if conn:
                cursor = conn.cursor()
                cursor.execute("SELECT MAX(id) FROM batch_info")
                result = cursor.fetchone()
                if result and result[0]:
                    next_batch_id = result[0] + 1
    except Exception as e:
        logger.error(f"Error getting next batch ID: {e}")

    # Create suggested name with format: filename (without extension) + "Batch X"
    suggested_name = f"{filename_without_ext} Batch {next_batch_id}"

    # Create input field for batch name
    name_edit = urwid.Edit("", suggested_name)
    
    # Calculate estimated time (rough estimate)
    # Assume 2 seconds per email for basic estimate
    est_seconds = email_count * 2
    if est_seconds < 60:
        est_time = f"{est_seconds} seconds"
    elif est_seconds < 3600:
        est_time = f"{est_seconds // 60} minutes, {est_seconds % 60} seconds"
    else:
        est_time = f"{est_seconds // 3600} hours, {(est_seconds % 3600) // 60} minutes"
    
    # Create batch setup dialog
    file_info = urwid.Text(f"File: {os.path.basename(file_path)}")
    count_info = urwid.Text(f"Emails to process: {email_count}")
    format_info = urwid.Text(f"Format check: {'Valid' if valid_format else 'Warning - some emails may be invalid'}")
    time_info = urwid.Text(f"Estimated completion time: {est_time}")
    
    # Show sample emails if available
    sample_text = ""
    if sample_emails:
        sample_text = "Sample emails:\n" + "\n".join(f"• {email}" for email in sample_emails)
    sample_info = urwid.Text(sample_text)

    # Show invalid emails if any (limited to first 10)
    invalid_text = ""
    if invalid_emails:
        display_count = min(10, len(invalid_emails))  # Show at most 10 invalid emails
        invalid_text = "Lines with invalid emails:\n" + "\n".join(
            f"Line {line}: {email}" for line, email in invalid_emails[:display_count]
        )
        if len(invalid_emails) > display_count:
            invalid_text += f"\n... and {len(invalid_emails) - display_count} more"
    invalid_info = urwid.Text(invalid_text)

    # Start and cancel buttons
    start_button = PlainButton("Start Batch Validation")
    cancel_button = PlainButton("Cancel [esc]")
    
    # Connect signals
    urwid.connect_signal(start_button, 'click', 
                       lambda button: start_batch_validation(file_path, name_edit.edit_text, email_count))
    urwid.connect_signal(cancel_button, 'click', go_back_one_level)
    
    # Style buttons
    start_button = urwid.AttrMap(start_button, None, focus_map="menu_focus")
    cancel_button = urwid.AttrMap(cancel_button, None, focus_map="menu_focus")
    
    # Create button row
    button_row = urwid.Columns([
        ('weight', 1, urwid.Text("")),
        ('pack', start_button),
        ('fixed', 3, urwid.Text(" ")),  # Space between buttons
        ('pack', cancel_button),
        ('weight', 1, urwid.Text(""))
    ])
    
    # Create setup dialog
    # Create setup dialog with both sample and invalid emails
    setup_pile = urwid.Pile([
        urwid.Divider(),
        file_info,
        urwid.Divider(),
        urwid.Text("Batch name:"),
        urwid.AttrMap(name_edit, "edit_unfocused", "edit_focused"),
        urwid.Divider(),
        count_info,
        format_info,
        time_info,
        urwid.Divider(),
        sample_info,
        urwid.Divider(),  # Add divider between sample and invalid emails
        invalid_info,     # Add the invalid emails section
        urwid.Divider(),
        button_row,
        urwid.Divider()
    ])
    
    # Update main widget
    main.original_widget = apply_box_style(
        urwid.Filler(setup_pile, valign='top'),
        title="Batch Setup"
    )

def start_batch_validation(file_path, batch_name, email_count):
    """Start the batch validation process with progress tracking"""
    global current_menu, menu_stack, total_emails
    
    # Store the total emails count in a variable accessible to process_complete
    total_emails = email_count
    
    if current_menu != "batch_progress":
        menu_stack.append(current_menu)
        current_menu = "batch_progress"
    
    # Prepare UI for progress tracking
    title_text = urwid.Text(f"Validating: {batch_name}")
    file_info = urwid.Text(f"File: {os.path.basename(file_path)}")
    status_text = urwid.Text("Status: Initializing...")
    count_text = urwid.Text(f"Processing 0 of {email_count} emails")
    success_text = urwid.Text("Successfully validated: 0")
    failed_text = urwid.Text("Failed validation: 0")
    time_text = urwid.Text("Elapsed time: 0s")
    
    # Progress bar
    progress_bar = urwid.ProgressBar("progress_bg", "progress_fg", 0, email_count)
    progress_bar_padding = urwid.Padding(progress_bar, left=1, right=1)
    
    # Action buttons (initially just Cancel)
    cancel_button = PlainButton("Cancel")
    # Connect signals
    urwid.connect_signal(cancel_button, 'click', lambda button: cancel_batch())
    
    # Button row
    button_row = urwid.Columns([
        ('weight', 1, urwid.Text("")),
        ('pack', urwid.AttrMap(cancel_button, None, focus_map="menu_focus")),
        ('weight', 1, urwid.Text(""))
    ])
    
    # Create the progress view with the updated layout
    progress_pile = urwid.Pile([
        urwid.Divider(),
        title_text,
        file_info,
        urwid.Divider(),
        success_text,
        failed_text,
        urwid.Divider(),
        time_text,
        count_text,
        status_text,
        urwid.Divider(),
        progress_bar_padding,  # Progress bar
        urwid.Divider(),
        button_row,
        urwid.Divider()
    ])
    
    # Update main widget
    main.original_widget = apply_box_style(
        urwid.Filler(progress_pile, valign='top', top=0, bottom=0),
        title="Batch Progress"
    )
    
    # Force redraw the screen before starting the process
    loop = get_main_loop()
    if loop:
        loop.draw_screen()
    
    # Create a new batch in the database
    from config import config
    cfg = config()
    batch_id = cfg.batch_info.create_batch(
        name=batch_name,
        source=file_path,
        total_emails=email_count
    )
    
    if not batch_id:
        show_error_dialog("Failed to create batch record in database.", show_batch_operations)
        return
    
    # Register the batch for cancellation tracking - if Core supports this
    if hasattr(Core, 'register_batch_for_cancellation'):
        Core.register_batch_for_cancellation(batch_id)
    
    # Set up variables for the processing loop
    processed = 0
    success_count = 0
    failed_count = 0
    start_time = time.time()
    batch_cancelled = [False]  # Use a list for mutability in nested functions
    
    # Add these variables for timer management
    elapsed_timer = [None]  # Store timer reference in a list for mutability
    
    # ADD THIS NEW FUNCTION - dedicated timer for elapsed time only
    def update_elapsed_time(*args):
        """Update ONLY the elapsed time display"""
        try:
            # Calculate elapsed time
            current_time = time.time()
            elapsed = current_time - start_time
        
            # Format time string
            if elapsed < 60:
                time_str = f"{elapsed:.1f}s"
            elif elapsed < 3600:
                minutes = int(elapsed // 60)
                seconds = int(elapsed % 60)
                time_str = f"{minutes}m {seconds}s"
            else:
                hours = int(elapsed // 3600)
                minutes = int((elapsed % 3600) // 60)
                time_str = f"{hours}h {minutes}m"
        
            # Update the time display
            time_text.set_text(f"Elapsed time: {time_str}")
        
            # Force screen update
            loop = get_main_loop()
            if loop and not batch_cancelled[0]:
                # Schedule next update in 1 second
                elapsed_timer[0] = loop.set_alarm_in(1, update_elapsed_time)
                loop.draw_screen()
        except Exception as e:
            logger.error(f"Error updating elapsed time: {e}")
    
    def cancel_batch():
        """Cancel the running batch"""
        batch_cancelled[0] = True
        status_text.set_text("Status: Cancelling...")
    
        # Cancel the elapsed time timer
        loop = get_main_loop()
        if loop and elapsed_timer[0]:
            loop.remove_alarm(elapsed_timer[0])
    
        # Call Core's cancellation function if available
        if hasattr(Core, 'cancel_batch_validation'):
            Core.cancel_batch_validation(batch_id)
    
        # Update the batch status in the database
        cfg.batch_info.update_batch_status(
            batch_id=batch_id,
            status="cancelled",
            processed=processed,
            success=success_count,
            failed=failed_count,
            error_message="Cancelled by user",
            completed=True
        )
    
        # Directly call process_complete to update UI
        loop = get_main_loop()
        if loop:
            loop.set_alarm_in(0.1, lambda *args: process_complete([], time.time() - start_time))
    
    def update_progress(percent, current, total):
        """Update UI progress indicators"""
        if batch_cancelled[0]:
            return
        
        # Update progress texts
        count_text.set_text(f"Processing {current} of {total} emails")
        progress_bar.set_completion(current)
    
        # Update success/failed counters
        success_text.set_text(f"Successfully validated: {success_count}")
        failed_text.set_text(f"Failed validation: {failed_count}")
    
        # Force redraw the screen
        loop = get_main_loop()
        if loop:
            loop.draw_screen()
    
    def process_complete(results, elapsed_time):
        """Handle processing completion"""
        nonlocal processed  # Make sure we can access the processed counter
    
        # Cancel the elapsed time timer
        loop = get_main_loop()
        if loop and elapsed_timer[0]:
            loop.remove_alarm(elapsed_timer[0])

        # Update final status
        if batch_cancelled[0]:
            status = "Cancelled"
        else:
            status = "Completed"

        status_text.set_text(f"Status: {status}")

        # Reset cancellation flag if all emails were processed
        if processed == total_emails:
            batch_cancelled[0] = False  # This ensures the progress update happens

        # Force a full progress update to ensure we show 100%
        if not batch_cancelled[0]:
            count_text.set_text(f"Processing {total_emails} of {total_emails} emails")
            progress_bar.set_completion(total_emails)
            success_text.set_text(f"Successfully validated: {success_count}")
            failed_text.set_text(f"Failed validation: {failed_count}")

        # Update the batch status in the database
        cfg.batch_info.update_batch_status(
            batch_id=batch_id,
            status=status.lower(),
            processed=processed,
            success=success_count,
            failed=failed_count,
            completed=True
    )
    
        # Clean up batch cancellation tracking if Core supports it
        if hasattr(Core, 'cleanup_batch_cancellation'):
            Core.cleanup_batch_cancellation(batch_id)
        
        # Create a done button to view results
        done_button = PlainButton("View Results")
        urwid.connect_signal(done_button, 'click', 
              lambda button: show_batch_results(batch_id))
        
        # Create back button
        back_button = PlainButton("Back to Batch Menu")
        urwid.connect_signal(back_button, 'click', 
              lambda button: show_batch_operations())
        
        # Center the buttons horizontally on the screen
        button_row.contents.clear()
        button_row.contents.append((
            urwid.Columns([
                ('weight', 1, urwid.Text("")),  # Empty space for centering
                ('pack', urwid.AttrMap(done_button, None, focus_map="menu_focus")),
                ('fixed', 3, urwid.Text(" ")),  # Space between buttons
                ('pack', urwid.AttrMap(back_button, None, focus_map="menu_focus")),
                ('weight', 1, urwid.Text(""))  # Empty space for centering
            ], dividechars=1),  # Ensure proper spacing between buttons
            button_row.options('weight', 1)  # Changed from 'pack' to 'weight' to fill the width
        ))
    
    # Force a final UI update
    if loop:
        loop.draw_screen()
    
    # Run the batch processing in background to keep UI responsive
    def process_batch():
        nonlocal processed, success_count, failed_count
        
        try:
            # Update database status
            cfg.batch_info.update_batch_status(
                batch_id=batch_id,
                status="processing"
            )
            
            # Get batch size from config or use default - INCREASE DEFAULT SIZE
            try:
                batch_size = cfg.app_setting.get('batch_processing', 'batch_size', 250)
            except:
                batch_size = 250  # Larger batch size for better performance
            
            # Read emails from file
            with open(file_path, 'r') as f:
                emails = [line.strip() for line in f if line.strip()]
            
            # Process emails in batches
            total_emails = len(emails)
            results = []
            
            # Connect to database for direct insertion
            conn = cfg.connect()
            if not conn:
                raise Exception("Failed to connect to database")
            
            # Process in parallel using ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=cfg.thread_pool_setting.max_worker_threads) as executor:
                # Submit all validation tasks to the thread pool
                loop = get_main_loop()  # Get loop reference BEFORE using it
                if loop:
                    status_text.set_text(f"Status: Submitting validation jobs...")
                    loop.draw_screen()  # Force immediate refresh
                    
                    # Submit all jobs at once
                    future_to_email = {executor.submit(Core.validate_email, email, batch_id=batch_id): email 
                                     for email in emails}
                
                # Process results as they complete (real-time updates)
                for i, future in enumerate(as_completed(future_to_email), 1):
                    # Check cancellation flag frequently
                    if batch_cancelled[0]:
                        logger.info(f"Batch {batch_id}: Cancellation detected, stopping processing")
                        break
                        
                    try:
                        email = future_to_email[future]
                        result = future.result()
                        results.append(result)
                        
                        # Count result immediately 
                        if "Email likely exists" in result:
                            success_count += 1
                        else:
                            failed_count += 1
                        
                        # Update UI for EACH completed email
                        processed = i
                        percent = int(processed / total_emails * 100)
                        
                        # Update progress with more efficient UI drawing
                        update_progress(percent, processed, total_emails)
                        
                        # Update status with current email
                        status_text.set_text(f"Status: Processed {email}")
                        
                        # Every 10 emails, commit to database
                        if i % 10 == 0 and conn:
                            try:
                                conn.commit()
                                logger.debug(f"Batch {batch_id}: Committed {i} records to database")
                            except Exception as commit_error:
                                logger.error(f"Error committing to database at record {i}: {commit_error}")
                        
                    except Exception as e:
                        logger.error(f"Error processing email: {e}")
                        failed_count += 1
                
                # Final database commit with verification
                if conn:
                    try:
                        conn.commit()
                        logger.debug(f"Batch {batch_id}: Final commit of {processed} records complete")
                        
                        # Verify record count
                        cursor = conn.cursor()
                        cursor.execute("SELECT COUNT(*) FROM email_validation_records WHERE batch_id = ?", (batch_id,))
                        db_count = cursor.fetchone()[0]
                        
                        if db_count != processed:
                            logger.warning(f"Record count mismatch! UI shows {processed} but database has {db_count} records")
                            # Attempt to reconcile
                            processed = db_count
                    except Exception as final_error:
                        logger.error(f"Error during final database commit: {final_error}")
            
            # Calculate elapsed time
            elapsed_time = time.time() - start_time
            
            # Schedule completion UI update with a slight delay
            loop = get_main_loop()
            if loop:
                # Make sure to call process_complete even if other errors occur
                loop.set_alarm_in(0.1, lambda *args: process_complete(results, elapsed_time))
                
        except Exception as exc:
            error_message = str(exc)  # Store in a variable that will persist
            logger.error(f"Error in batch processing: {error_message}", exc_info=True)
            
            # Cancel the elapsed time timer
            loop = get_main_loop()
            if loop and elapsed_timer[0]:
                loop.remove_alarm(elapsed_timer[0])
            
            # Update batch status with error
            cfg.batch_info.update_batch_status(
                batch_id=batch_id,
                status="failed",
                processed=processed,
                success=success_count,
                failed=failed_count,
                error_message=error_message,
                completed=True
            )
            
            # Show error dialog in main thread with a slight delay
            loop = get_main_loop()
            if loop:
                loop.set_alarm_in(0.1, lambda *args: show_error_dialog(
                    f"Error during batch processing: {error_message}",
                    show_batch_operations
                ))
    
    # Start the elapsed time timer - ONLY INITIALIZE ONCE
    loop = get_main_loop()
    if loop:
        elapsed_timer[0] = loop.set_alarm_in(0.1, update_elapsed_time)
    
    # Start processing in a separate thread
    import threading
    processing_thread = threading.Thread(target=process_batch)
    processing_thread.daemon = True
    processing_thread.start()

def show_batch_results(batch_id):
    """Display results of a specific batch using Core.display_logs"""
    global current_menu, menu_stack
    
    if current_menu != "batch_results":
        menu_stack.append(current_menu)
        current_menu = "batch_results"
    
    # Get batch information
    from config import config
    cfg = config()
    batch_info = cfg.batch_info.get_batch(batch_id)
    
    if not batch_info:
        show_error_dialog("Batch information not found.", show_batch_operations)
        return
    
    # Create a text widget to capture output
    old_stdout = sys.stdout
    result_capture = io.StringIO()
    sys.stdout = result_capture

    try:
        # Call the Core.display_logs function
        Core.display_logs(batch_id)
    except Exception as e:
        logger.error(f"Error in function: {e}")
    finally:
        sys.stdout = old_stdout  # Ensure stdout is always restored

    captured_output = result_capture.getvalue()
    
    # Ensure the output isn't empty
    if not captured_output.strip():
        captured_output = f"No display data found for batch ID {batch_id}"
        logger.warning(f"Empty output when displaying batch {batch_id}")
    
    # Set font to monospace to preserve tabulate grid formatting
    text_widget = urwid.Text(('monospace', captured_output))
    
    # Create a list walker with the text widget
    list_walker = urwid.SimpleListWalker([text_widget])
    list_box = urwid.ListBox(list_walker)
    scrollable_area = urwid.ScrollBar(list_box)
    
    # Increase height to show more content
    content_box = urwid.BoxAdapter(scrollable_area, 25)
    
    # Back button
    back_button = PlainButton("Back [esc]")
    urwid.connect_signal(back_button, 'click', go_back_one_level)
    
    button_container = urwid.Columns([
        ('weight', 1, urwid.Text("")),
        ('pack', urwid.AttrMap(back_button, None, focus_map="menu_focus")),
        ('weight', 1, urwid.Text(""))
    ])
    
    # Create the results view
    results_view = urwid.Pile([
        content_box,
        urwid.Divider(),
        button_container,
        urwid.Divider()
    ])
    
    # Update main widget
    batch_name = batch_info.get('name', 'Unnamed Batch')
    main.original_widget = apply_box_style(
        urwid.Filler(results_view, valign='top', top=0, bottom=0),
        title=f"Batch Results: {batch_name}"
    )
    
    # Ensure the monospace attribute is defined in your palette
    # This should be added where you define your urwid palette
    loop = get_main_loop()
    if loop and hasattr(loop, 'screen'):
        try:
            # Try to update the palette with monospace attribute if needed
            if not any(attr[0] == 'monospace' for attr in loop.screen.register_palette):
                loop.screen.register_palette_entry('monospace', 'white', 'black', 'standout')
        except:
            logger.debug("Failed to update palette with monospace attribute")
            pass

def format_timestamp(timestamp_str):
    """Format ISO timestamp to DD-MM-YYYY HH:MM:SS format"""
    if not timestamp_str:
        return 'N/A'
    
    try:
        # Parse ISO format timestamp
        dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        # Format to more readable format with time
        return dt.strftime('%d-%m-%Y %H:%M:%S')
    except ValueError:
        # If timestamp isn't valid ISO format, return as is
        return timestamp_str

def calculate_elapsed_time(start_timestamp, end_timestamp):
    """Calculate and format elapsed time between two timestamps in H:M:S format"""
    if not start_timestamp or not end_timestamp or end_timestamp == 'N/A':
        return "N/A"
    
    try:
        # Parse ISO format timestamps
        start_dt = datetime.fromisoformat(start_timestamp.replace('Z', '+00:00'))
        end_dt = datetime.fromisoformat(end_timestamp.replace('Z', '+00:00'))
        
        # Calculate time difference
        elapsed = end_dt - start_dt
        
        # Format as H:M:S
        hours, remainder = divmod(int(elapsed.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        
        return f"{hours:02}:{minutes:02}:{seconds:02}"
    except Exception:
        return "N/A"

def show_batch_history():
    """Display list of all batch operations"""
    global current_menu, menu_stack
    
    if current_menu != "batch_history":
        menu_stack.append(current_menu)
        current_menu = "batch_history"
    
    # Get list of batches
    from config import config
    cfg = config()
    batches = cfg.batch_info.list_batches(limit=100)
    
    if not batches:
        # No batches found
        message = urwid.Text("No batch operations found.")
        back_button = PlainButton("Back [esc]")
        urwid.connect_signal(back_button, 'click', go_back_one_level)
        
        button_container = urwid.Columns([
            ('weight', 1, urwid.Text("")),
            ('pack', urwid.AttrMap(back_button, None, focus_map="menu_focus")),
            ('weight', 1, urwid.Text(""))
        ])
        
        view = urwid.Pile([
            urwid.Divider(),
            message,
            urwid.Divider(),
            button_container
        ])
        
        main.original_widget = apply_box_style(
            urwid.Filler(view, valign='middle'),
            title="Batch History"
        )
        return
    
    # Create table header with new columns - separate from scrollable content
    header = urwid.Columns([
      # ('weight', 1, urwid.Text(('bold_title', "#"))),
        ('weight', 1, urwid.Text(('bold_title', "Name"))),
        ('weight', 1, urwid.Text(('bold_title', "Start time"))),
      # ('weight', 1, urwid.Text(('bold_title', "End time"))),
        ('weight', 1, urwid.Text(('bold_title', "Elapsed time"))),
        ('weight', 1, urwid.Text(('bold_title', "Status"))),
        ('weight', 1, urwid.Text(('bold_title', "Total"))),
        ('weight', 1, urwid.Text(('bold_title', "Processed"))),
        ('weight', 1, urwid.Text(('bold_title', "Valid %")))
    ])
    
    # Apply padding and styling to the header
    header_with_divider = urwid.Pile([
        header,
        urwid.Divider('─')  # Use box drawing character for a cleaner divider line
    ])
    
    # Create list of batch items - only the rows, not the header
    batch_rows = []
    
    for batch in batches:
        # Get batch ID
        batch_id = batch.get('id', 'N/A')
        
        # Calculate success percentage
        total = batch.get('total_emails', 0)
        processed = batch.get('processed_emails', 0)
        success = batch.get('success_count', 0)
        
        if processed > 0:
            success_percent = f"{(success / processed) * 100:.1f}%"
        else:
            success_percent = "N/A"
        
        # Format timestamps 
        created = format_timestamp(batch.get('created_at', ''))
        completed = format_timestamp(batch.get('completed_at', ''))

        # Calculate elapsed time directly from timestamps
        elapsed_time = calculate_elapsed_time(
            batch.get('created_at', ''), 
            batch.get('completed_at', '')
        )
        
        # Get status with appropriate color
        status = batch.get('status', 'unknown').lower()
        if status == 'completed':
            status_text = (status.capitalize())
        elif status == 'processing':
            status_text = (status.capitalize())
        elif status == 'failed' or status == 'cancelled':
            status_text = (status.capitalize())
        else:
            status_text = status.capitalize()
        
        # Create row as a button
        row_text = urwid.Columns([
          # ('weight', 1, urwid.Text(str(batch_id))),
            ('weight', 1, urwid.Text(batch.get('name', 'Unnamed'))),
            ('weight', 1, urwid.Text(created)),
          # ('weight', 1, urwid.Text(completed)),
            ('weight', 1, urwid.Text(elapsed_time)),
            ('weight', 1, urwid.Text(status_text)),
            ('weight', 1, urwid.Text(str(total))),
            ('weight', 1, urwid.Text(str(processed))),
            ('weight', 1, urwid.Text(success_percent))
        ])
        
        # Create selectable row
        row_btn = BatchRowButton(row_text, batch_id)
        urwid.connect_signal(row_btn, 'click', 
                           lambda button, bid=batch_id: show_batch_results(bid))
        
        batch_rows.append(urwid.AttrMap(row_btn, None, focus_map="menu_focus"))
        batch_rows.append(urwid.Divider())
    
    # Create scrollable list for rows only
    batch_walker = urwid.SimpleListWalker(batch_rows)
    batch_listbox = urwid.ListBox(batch_walker)
    batch_with_scrollbar = urwid.ScrollBar(batch_listbox)
    
    # Make the scroll box fill the available space
    batch_box = urwid.BoxAdapter(batch_with_scrollbar, 23)  # Adjust height to leave space for header and footer
    
    # Back button
    back_button = PlainButton("Back [esc]")
    urwid.connect_signal(back_button, 'click', go_back_one_level)
    
    button_container = urwid.Columns([
        ('weight', 1, urwid.Text("")),
        ('pack', urwid.AttrMap(back_button, None, focus_map="menu_focus")),
        ('weight', 1, urwid.Text(""))
    ])
    
    # Create footer with proper spacing
    footer = urwid.Pile([
        urwid.Divider(),  # Space above button
        button_container,
        urwid.Divider()   # Space below button
    ])
    
    # Combine everything - header at top, scrollable rows in middle, footer at bottom
    history_view = urwid.Pile([
        ('pack', header_with_divider),  # Header takes minimal space
        ('weight', 1, batch_box),       # Batch rows expand to fill available space
        ('pack', footer)                # Footer takes minimal space
    ])
    
    # Update main widget
    main.original_widget = apply_box_style(
        urwid.Filler(history_view, valign='top', top=0, bottom=0),
        title="Batch History"
    )

# Custom widget for batch history rows
class BatchRowButton(urwid.WidgetWrap):
    signals = ['click']
    
    def __init__(self, content_widget, batch_id):
        self.content = content_widget
        self.batch_id = batch_id
        super().__init__(content_widget)
    
    def selectable(self):
        return True
    
    def keypress(self, size, key):
        if key == 'enter':
            urwid.emit_signal(self, 'click', self, self.batch_id)
            return None
        return key
    
    def mouse_event(self, size, event, button, x, y, focus):
        if button == 1:
            urwid.emit_signal(self, 'click', self, self.batch_id)
            return True
        return False

def show_error_dialog(message, callback):
    """Show an error dialog with a message and OK button"""
    # Create error message
    error_text = urwid.Text(message, align='center')
    
    # OK button
    ok_button = PlainButton("OK")
    urwid.connect_signal(ok_button, 'click', lambda button: callback())
    
    # Create button container
    button_container = urwid.Columns([
        ('weight', 1, urwid.Text("")),
        ('pack', urwid.AttrMap(ok_button, None, focus_map="menu_focus")),
        ('weight', 1, urwid.Text(""))
    ])
    
    # Create error dialog
    error_pile = urwid.Pile([
        urwid.Divider(),
        error_text,
        urwid.Divider(),
        button_container,
        urwid.Divider()
    ])
    
    # Update main widget
    main.original_widget = apply_box_style(
        urwid.Filler(error_pile, valign='middle'),
        title="Error"
    )

def show_validation_records():
    """Display Email Validation Records with filtering options"""
    global current_menu, menu_stack
    
    # Update menu tracking
    if current_menu != "validation_records":
        menu_stack.append(current_menu)
        current_menu = "validation_records"
    
    # Create filter options
    view_options = []
    
    # 1. Create buttons for different view options
    all_records_btn = PlainButton("Show All Records")
    custom_filter_btn = PlainButton("Custom Filter View")
    
    # Connect signals to buttons
    urwid.connect_signal(all_records_btn, 'click', lambda button: show_all_records())
    urwid.connect_signal(custom_filter_btn, 'click', lambda button: show_custom_filtered_records())
    
    # Style buttons
    all_records_btn = urwid.AttrMap(all_records_btn, None, focus_map="menu_focus")
    custom_filter_btn = urwid.AttrMap(custom_filter_btn, None, focus_map="menu_focus")
    
    # Calculate width for consistent layout
    max_length = max(len("Show All Records"), len("Custom Filter View"))
    menu_width = max_length + 4  # Add padding
    
    # Create centered button containers
    all_records_container = urwid.Columns([
        ('weight', 1, urwid.Text("")),
        ('fixed', menu_width, all_records_btn),
        ('weight', 1, urwid.Text(""))
    ])
    
    custom_filter_container = urwid.Columns([
        ('weight', 1, urwid.Text("")),
        ('fixed', menu_width, custom_filter_btn),
        ('weight', 1, urwid.Text(""))
    ])
    
    # Back button
    back_button = PlainButton("Back [esc]")
    urwid.connect_signal(back_button, 'click', go_back_one_level)
    
    back_container = urwid.Columns([
        ('weight', 1, urwid.Text("")),
        ('fixed', menu_width, urwid.AttrMap(back_button, None, focus_map="menu_focus")),
        ('weight', 1, urwid.Text(""))
    ])
    
    # Create view options layout
    view_options = [
        urwid.Divider(),
        urwid.Text("Select a view option:", align='center'),
        urwid.Divider(),
        all_records_container,
        urwid.Divider(),
        custom_filter_container,
        urwid.Divider(),
        back_container
    ]
    
    # Create a pile with the view options
    options_pile = urwid.Pile(view_options)
    
    # Update main widget
    main.original_widget = apply_box_style(
        urwid.Filler(options_pile, valign='top'),
        title="Email Validation Records"
    )

def show_all_records():
    """Display all email validation records without filtering"""
    # Create a text widget to capture output
    old_stdout = sys.stdout
    result_capture = io.StringIO()
    sys.stdout = result_capture
    
    # Fix column definitions before displaying logs
    try:
        Core.load_batch_column_settings()
    except Exception as e:
        logger.error(f"Error fixing column definitions: {e}")
    
    # Call the Core.py function to display logs
    Core.display_logs_all()
    
    # Restore stdout
    sys.stdout = old_stdout
    captured_output = result_capture.getvalue()
    
    # Display the captured output in a scrollable text widget
    text_widget = urwid.Text(captured_output)
    list_walker = urwid.SimpleListWalker([text_widget])
    list_box = urwid.ListBox(list_walker)
    scrollable_area = urwid.ScrollBar(list_box)
    content_box = urwid.BoxAdapter(scrollable_area, 25)
    
    # Back button
    back_button = PlainButton("Back [esc]")
    urwid.connect_signal(back_button, 'click', go_back_one_level)
    
    button_container = urwid.Columns([
        ('weight', 1, urwid.Text("")),
        ('pack', urwid.AttrMap(back_button, None, focus_map="menu_focus")),
        ('weight', 1, urwid.Text(""))
    ])
    
    view = urwid.Pile([
        content_box,
        urwid.Divider(),
        button_container,
        urwid.Divider()
    ])
    
    main.original_widget = apply_box_style(
        urwid.Filler(view, valign='top', top=0, bottom=0),
        title="All Email Validation Records"
    )

def show_custom_filtered_records():
    """Show custom filtered email validation records"""
    global current_menu, menu_stack
    
    # Update menu tracking
    if current_menu != "custom_filter":
        menu_stack.append(current_menu)
        current_menu = "custom_filter"
    
    # Filter options without numbers
    filter_options = [
        "by Date Range",
        "by Domain",
        "by Confidence Level",
        "by Email Text",
        "Results list with filters",
        "Reset Filters"
    ]
    
    # Initialize filter state if not exists
    if not hasattr(show_custom_filtered_records, "filter_state"):
        show_custom_filtered_records.filter_state = {
            "date_range": None,
            "domain_filter": None,
            "confidence_levels": None,
            "email_search": None
        }
    
    # Create status text showing active filters
    filter_summary = []
    if show_custom_filtered_records.filter_state["date_range"]:
        start_date, end_date = show_custom_filtered_records.filter_state["date_range"]
        date_parts = []
        if start_date:
            date_parts.append(f"from {start_date.strftime('%Y-%m-%d')}")
        if end_date:
            date_parts.append(f"to {end_date.strftime('%Y-%m-%d')}")
        filter_summary.append("Date: " + " ".join(date_parts))
    
    if show_custom_filtered_records.filter_state["domain_filter"]:
        filter_summary.append(f"Domain: {show_custom_filtered_records.filter_state['domain_filter']}")
    
    if show_custom_filtered_records.filter_state["confidence_levels"]:
        levels = show_custom_filtered_records.filter_state["confidence_levels"]
        filter_summary.append(f"Confidence: {', '.join(levels)}")
    
    if show_custom_filtered_records.filter_state["email_search"]:
        filter_summary.append(f"Email text: {show_custom_filtered_records.filter_state['email_search']}")
    
    filter_status = "No filters applied"
    if filter_summary:
        filter_status = " | ".join(filter_summary)
    
    # Calculate the width needed for the longest menu item
    max_length = max(len(option) for option in filter_options)
    menu_width = max_length + 4  # Add some padding
    
    # Create menu items with proper centering
    menu_items = []
    
    # Add active filter status (centered)
    menu_items.append(urwid.Divider())
    menu_items.append(urwid.Text(("bold_title", "Active Filters:"), align='center'))
    menu_items.append(urwid.Text(filter_status, align='center'))
    menu_items.append(urwid.Divider())
    
    # Add filter options with proper centering
    for i, option in enumerate(filter_options):
        button = PlainButton(option)
        
        # Connect button signals based on index instead of parsing number from text
        if i == 0:  # Filter by Date Range
            urwid.connect_signal(button, 'click', lambda btn: show_date_range_filter())
        elif i == 1:  # Filter by Domain
            urwid.connect_signal(button, 'click', lambda btn: show_domain_filter())
        elif i == 2:  # Filter by Confidence Level
            urwid.connect_signal(button, 'click', lambda btn: show_confidence_filter())
        elif i == 3:  # Filter by Email Text
            urwid.connect_signal(button, 'click', lambda btn: show_email_text_filter())
        elif i == 4:  # View Results with Current Filters
            urwid.connect_signal(button, 'click', lambda btn: display_filtered_results())
        elif i == 5:  # Reset All Filters
            urwid.connect_signal(button, 'click', lambda btn: reset_filters())
        
        # Create centered button container like other menus
        button_container = urwid.Columns([
            ('weight', 1, urwid.Text("")),
            ('fixed', menu_width, urwid.AttrMap(button, None, focus_map="menu_focus")),
            ('weight', 1, urwid.Text(""))
        ])
        
        menu_items.append(button_container)
        menu_items.append(urwid.Divider())
        
        # Add an extra divider between "Filter by Email Text" and "View Results with Current Filters"
        if i == 3:  # After "Filter by Email Text"
            menu_items.append(urwid.Divider())  # Add an extra divider for more spacing
    
    # Back button (centered)
    back_button = PlainButton("Back [esc]")
    urwid.connect_signal(back_button, 'click', go_back_one_level)
    
    back_container = urwid.Columns([
        ('weight', 1, urwid.Text("")),
        ('fixed', menu_width, urwid.AttrMap(back_button, None, focus_map="menu_focus")),
        ('weight', 1, urwid.Text(""))
    ])
    
    menu_items.append(back_container)
    
    # Create menu
    menu_pile = urwid.Pile(menu_items)
    
    # Update main widget
    main.original_widget = apply_box_style(
        urwid.Filler(menu_pile, valign='top'),
        title="Custom Log Filter"
    )

def show_date_range_filter():
    """Show date range filter options"""
    global current_menu, menu_stack
    
    # Update menu tracking
    if current_menu != "date_filter":
        menu_stack.append(current_menu)
        current_menu = "date_filter"
    
    # Get current filter state
    current_filter = getattr(show_custom_filtered_records, "filter_state", {})
    current_date_range = current_filter.get("date_range", (None, None))
    
    # Create date input fields
    from datetime import datetime
    
    # Format current values if they exist
    start_date_str = ""
    end_date_str = ""
    if current_date_range:
        start_date, end_date = current_date_range
        if start_date:
            start_date_str = start_date.strftime("%Y-%m-%d")
        if end_date:
            end_date_str = end_date.strftime("%Y-%m-%d")
    
    start_edit = urwid.Edit("", start_date_str)
    end_edit = urwid.Edit("", end_date_str)
    
    # Create save button
    save_button = PlainButton("Apply Filter")
    def on_save_clicked(button):
        # Parse date inputs
        try:
            start_date = None
            end_date = None
            
            if start_edit.edit_text.strip():
                start_date = datetime.strptime(start_edit.edit_text.strip(), "%Y-%m-%d")
                start_date = start_date.replace(hour=0, minute=0, second=0)  # Start of day
            
            if end_edit.edit_text.strip():
                end_date = datetime.strptime(end_edit.edit_text.strip(), "%Y-%m-%d")
                end_date = end_date.replace(hour=23, minute=59, second=59)  # End of day
            
            # Save filter
            show_custom_filtered_records.filter_state["date_range"] = (start_date, end_date) if start_date or end_date else None
            
            # Go back to main filter menu
            show_custom_filtered_records()
            
        except ValueError:
            # Show error for invalid date format
            show_error_dialog("Invalid date format. Please use YYYY-MM-DD format.", show_date_range_filter)
            logger.error("Invalid date format. Please use YYYY-MM-DD format.", exc_info=True)
    
    # Connect signals
    
    urwid.connect_signal(save_button, 'click', on_save_clicked)
    
    # Create clear button
    clear_button = PlainButton("Clear Date Filter")
    def on_clear_clicked(button):
        show_custom_filtered_records.filter_state["date_range"] = None
        show_custom_filtered_records()
    
    urwid.connect_signal(clear_button, 'click', on_clear_clicked)
    
    # Create cancel button
    cancel_button = PlainButton("Cancel [esc]")
    urwid.connect_signal(cancel_button, 'click', go_back_one_level)
    
    # Layout
    pile = urwid.Pile([
        urwid.Text("Date Range Filter"),
        urwid.Divider(),
        urwid.Text("Start date (YYYY-MM-DD, leave empty for no start limit):"),
        urwid.AttrMap(start_edit, "edit_unfocused", "edit_focused"),
        urwid.Divider(),
        urwid.Text("End date (YYYY-MM-DD, leave empty for no end limit):"),
        urwid.AttrMap(end_edit, "edit_unfocused", "edit_focused"),
        urwid.Divider(),
        urwid.Columns([
            ('weight', 1, urwid.Text("")),
            ('pack', urwid.AttrMap(save_button, None, focus_map="menu_focus")),
            ('fixed', 3, urwid.Text(" ")),
            ('pack', urwid.AttrMap(clear_button, None, focus_map="menu_focus")),
            ('fixed', 3, urwid.Text(" ")),
            ('pack', urwid.AttrMap(cancel_button, None, focus_map="menu_focus")),
            ('weight', 1, urwid.Text(""))
        ])
    ])
    
    # Update main widget
    main.original_widget = apply_box_style(
        urwid.Filler(pile, valign='top'),
        title="Date Range Filter"
    )

def show_domain_filter():
    """Show domain filter options"""
    global current_menu, menu_stack
    
    # Update menu tracking
    if current_menu != "domain_filter":
        menu_stack.append(current_menu)
        current_menu = "domain_filter"
    
    # Get current filter state
    current_filter = getattr(show_custom_filtered_records, "filter_state", {})
    current_domain = current_filter.get("domain_filter", "")
    
    # Create domain input field
    domain_edit = urwid.Edit("", current_domain if current_domain else "")
    
    # Create save button
    save_button = PlainButton("Apply Filter")
    def on_save_clicked(button):
        domain = domain_edit.edit_text.strip()
        show_custom_filtered_records.filter_state["domain_filter"] = domain if domain else None
        show_custom_filtered_records()
    
    urwid.connect_signal(save_button, 'click', on_save_clicked)
    
    # Create clear button
    clear_button = PlainButton("Clear Domain Filter")
    def on_clear_clicked(button):
        show_custom_filtered_records.filter_state["domain_filter"] = None
        show_custom_filtered_records()
    
    urwid.connect_signal(clear_button, 'click', on_clear_clicked)
    
    # Create cancel button
    cancel_button = PlainButton("Cancel [esc]")
    urwid.connect_signal(cancel_button, 'click', go_back_one_level)
    
    # Layout
    pile = urwid.Pile([
        urwid.Text("Domain Filter"),
        urwid.Divider(),
        urwid.Text("Enter domains to filter (comma-separated, e.g. gmail.com,yahoo.com):"),
        urwid.AttrMap(domain_edit, "edit_unfocused", "edit_focused"),
        urwid.Divider(),
        urwid.Columns([
            ('weight', 1, urwid.Text("")),
            ('pack', urwid.AttrMap(save_button, None, focus_map="menu_focus")),
            ('fixed', 3, urwid.Text(" ")),
            ('pack', urwid.AttrMap(clear_button, None, focus_map="menu_focus")),
            ('fixed', 3, urwid.Text(" ")),
            ('pack', urwid.AttrMap(cancel_button, None, focus_map="menu_focus")),
            ('weight', 1, urwid.Text(""))
        ])
    ])
    
    # Update main widget
    main.original_widget = apply_box_style(
        urwid.Filler(pile, valign='top'),
        title="Domain Filter"
    )

def show_confidence_filter():
    """Show confidence level filter options"""
    global current_menu, menu_stack
    
    # Update menu tracking
    if current_menu != "confidence_filter":
        menu_stack.append(current_menu)
        current_menu = "confidence_filter"
    
    # Add the missing import and config instantiation
    from config import config
    cfg = config()
    
    # Get current filter state
    current_filter = getattr(show_custom_filtered_records, "filter_state", {})
    current_levels = current_filter.get("confidence_levels", [])
    
    # Get available confidence levels and their counts from database
    with cfg.connect() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT 
                CASE 
                    WHEN confidence_score BETWEEN 0 AND 20 THEN 'Very Low (0-20)'
                    WHEN confidence_score BETWEEN 21 AND 40 THEN 'Low (21-40)'
                    WHEN confidence_score BETWEEN 41 AND 60 THEN 'Medium (41-60)'
                    WHEN confidence_score BETWEEN 61 AND 80 THEN 'High (61-80)'
                    WHEN confidence_score BETWEEN 81 AND 100 THEN 'Very High (81-100)'
                    ELSE 'Unknown'
                END as confidence_level,
                COUNT(*) as count
            FROM email_validation_records
            GROUP BY confidence_level
            ORDER BY MIN(confidence_score)
        """)
        confidence_counts = cursor.fetchall()
        
        # Create checkboxes for each confidence level
        checkboxes = []
        for level in confidence_counts:
            level_text = f"{level['confidence_level']} ({level['count']} emails)"
            is_checked = level['confidence_level'] in current_levels if current_levels else False
            checkbox = urwid.CheckBox(level_text, state=is_checked)
            checkboxes.append(('pack', checkbox))
            checkboxes.append(('pack', urwid.Divider()))
        
        # Create checkbox list
        checkbox_pile = urwid.Pile(checkboxes)
        
        # Create save button
        save_button = PlainButton("Apply Filter")
        def on_save_clicked(button):
            # Collect selected confidence levels
            selected_levels = []
            for i in range(0, len(checkboxes), 2):
                if i+1 < len(checkboxes):
                    checkbox = checkboxes[i][1]
                    if checkbox.state:
                        level_text = checkbox.label
                        # Extract just the level name (without count)
                        level_name = level_text.split(" (")[0]
                        selected_levels.append(level_name)
            
            # Save filter
            show_custom_filtered_records.filter_state["confidence_levels"] = selected_levels if selected_levels else None
            
            # Return to main filter menu
            show_custom_filtered_records()
        
        urwid.connect_signal(save_button, 'click', on_save_clicked)
        
        # Create clear button
        clear_button = PlainButton("Clear Confidence Filter")
        def on_clear_clicked(button):
            show_custom_filtered_records.filter_state["confidence_levels"] = None
            show_custom_filtered_records()
        
        urwid.connect_signal(clear_button, 'click', on_clear_clicked)
        
        # Create cancel button
        cancel_button = PlainButton("Cancel [esc]")
        urwid.connect_signal(cancel_button, 'click', go_back_one_level)
        
        # Layout
        pile = urwid.Pile([
            urwid.Text("Confidence Level Filter"),
            urwid.Divider(),
            urwid.Text("Select confidence levels to include:"),
            urwid.Divider(),
            checkbox_pile,
            urwid.Divider(),
            urwid.Columns([
                ('weight', 1, urwid.Text("")),
                ('pack', urwid.AttrMap(save_button, None, focus_map="menu_focus")),
                ('fixed', 3, urwid.Text(" ")),
                ('pack', urwid.AttrMap(clear_button, None, focus_map="menu_focus")),
                ('fixed', 3, urwid.Text(" ")),
                ('pack', urwid.AttrMap(cancel_button, None, focus_map="menu_focus")),
                ('weight', 1, urwid.Text(""))
            ])
        ])
        
        # Update main widget
        main.original_widget = apply_box_style(
            urwid.Filler(pile, valign='top'),
            title="Confidence Level Filter"
        )    

def show_email_text_filter():
    """Show email text filter options"""
    global current_menu, menu_stack
    
    # Update menu tracking
    if current_menu != "email_filter":
        menu_stack.append(current_menu)
        current_menu = "email_filter"
    
    # Get current filter state
    current_filter = getattr(show_custom_filtered_records, "filter_state", {})
    current_search = current_filter.get("email_search", "")
    
    # Create search input field
    search_edit = urwid.Edit("", current_search if current_search else "")
    
    # Create save button
    save_button = PlainButton("Apply Filter")
    def on_save_clicked(button):
        search_text = search_edit.edit_text.strip()
        show_custom_filtered_records.filter_state["email_search"] = search_text if search_text else None
        show_custom_filtered_records()
    
    urwid.connect_signal(save_button, 'click', on_save_clicked)
    
    # Create clear button
    clear_button = PlainButton("Clear Text Filter")
    def on_clear_clicked(button):
        show_custom_filtered_records.filter_state["email_search"] = None
        show_custom_filtered_records()
    
    urwid.connect_signal(clear_button, 'click', on_clear_clicked)
    
    # Create cancel button
    cancel_button = PlainButton("Cancel [esc]")
    urwid.connect_signal(cancel_button, 'click', go_back_one_level)
    
    # Layout
    pile = urwid.Pile([
        urwid.Text("Email Text Filter"),
        urwid.Divider(),
        urwid.Text("Enter text to search in email addresses (comma-separated for multiple terms):"),
        urwid.AttrMap(search_edit, "edit_unfocused", "edit_focused"),
        urwid.Divider(),
        urwid.Columns([
            ('weight', 1, urwid.Text("")),
            ('pack', urwid.AttrMap(save_button, None, focus_map="menu_focus")),
            ('fixed', 3, urwid.Text(" ")),
            ('pack', urwid.AttrMap(clear_button, None, focus_map="menu_focus")),
            ('fixed', 3, urwid.Text(" ")),
            ('pack', urwid.AttrMap(cancel_button, None, focus_map="menu_focus")),
            ('weight', 1, urwid.Text(""))
        ])
    ])
    
    # Update main widget
    main.original_widget = apply_box_style(
        urwid.Filler(pile, valign='top'),
        title="Email Text Filter"
    )

def display_filtered_results():
    """Display results with current filters"""
    global current_menu, menu_stack
    
    # Update menu tracking
    if current_menu != "filter_results":
        menu_stack.append(current_menu)
        current_menu = "filter_results"
    
    # Get filter state
    filters = getattr(show_custom_filtered_records, "filter_state", {})
    
    # Create a text widget to capture output
    old_stdout = sys.stdout
    result_capture = io.StringIO()
    sys.stdout = result_capture
    
    try:
        # Call the Core's internal display function
        from tabulate import tabulate
        
        # Get filtered results but don't display them yet
        results = Core.display_logs_custom_gui(
            date_range=filters["date_range"],
            domain_filter=filters["domain_filter"],
            confidence_levels=filters["confidence_levels"],
            email_search=filters["email_search"]
        )
        
        # Format the results using tabulate, similar to Core's display functions
        if results['rows']:
            # Print filter summary
            print(f"\nFiltered Email Validation Logs: {results['filter_summary']}\n")
            
            # Display formatted data with tabulate
            print(tabulate(
                results['rows'],
                headers=results['headers'],
                tablefmt='grid',
                numalign='left',
                stralign='left'
            ))
            
            print(f"\nShowing {results['record_count']} of {results['total_count']} filtered records.")
        else:
            print("\nNo matching records found.")
        
        # Restore stdout
        sys.stdout = old_stdout
        captured_output = result_capture.getvalue()
        
    except Exception as e:
        # Make sure stdout is restored even if an error occurs
        sys.stdout = old_stdout
        logger.error(f"Error showing filtered results: {str(e)}")
        captured_output = f"Error displaying filtered results: {str(e)}"
    
    # Display the captured output in a scrollable text widget
    text_widget = urwid.Text(captured_output)
    list_walker = urwid.SimpleListWalker([text_widget])
    list_box = urwid.ListBox(list_walker)
    scrollable_area = urwid.ScrollBar(list_box)
    content_box = urwid.BoxAdapter(scrollable_area, 25)
    
    # Back button
    back_button = PlainButton("Back [esc]")
    urwid.connect_signal(back_button, 'click', go_back_one_level)
    
    button_container = urwid.Columns([
        ('weight', 1, urwid.Text("")),
        ('pack', urwid.AttrMap(back_button, None, focus_map="menu_focus")),
        ('weight', 1, urwid.Text(""))
    ])
    
    view = urwid.Pile([
        content_box,
        urwid.Divider(),
        button_container,
        urwid.Divider()
    ])
    
    main.original_widget = apply_box_style(
        urwid.Filler(view, valign='top', top=0, bottom=0),
        title="Filtered Email Records"
    )

def reset_filters():
    """Reset all filters to default values"""
    show_custom_filtered_records.filter_state = {
        "date_range": None,
        "domain_filter": None,
        "confidence_levels": None,
        "email_search": None
    }
    show_custom_filtered_records()

def show_audit_log():
    """Display Audit Log using a grid layout"""
    global current_menu, menu_stack
    
    # Update menu tracking
    if current_menu != "audit_log":
        menu_stack.append(current_menu)
        current_menu = "audit_log"
    
    logs_dir = os.path.join(os.getcwd(), 'logs')
    
    # Check if logs directory exists
    if not os.path.exists(logs_dir):
        # Display error message (existing code)
        message = urwid.Text("No logs directory found. Audit logs are not available.")
        back_button = PlainButton("Back [esc]")
        urwid.connect_signal(back_button, 'click', go_back_one_level)
        
        button_container = urwid.Columns([
            ('weight', 1, urwid.Text("")),
            ('pack', urwid.AttrMap(back_button, None, focus_map="menu_focus")),
            ('weight', 1, urwid.Text(""))
        ])
        
        view = urwid.Pile([
            urwid.Divider(),
            message,
            urwid.Divider(),
            button_container
        ])
        
        main.original_widget = apply_box_style(
            urwid.Filler(view, valign='middle'),
            title="Audit Log"
        )
        return
    
    # Get list of log files (excluding errors.log)
    log_files = []
    try:
        log_files = [f for f in os.listdir(logs_dir) 
                     if os.path.isfile(os.path.join(logs_dir, f)) 
                     and (f.endswith('.log') or f.endswith('.txt'))
                     and f != "errors.log"]
    except Exception as e:
        logger.error(f"Error listing log files: {e}")
    
    if not log_files:
        # Display error message (existing code)
        message = urwid.Text("No log files found in the logs directory.")
        back_button = PlainButton("Back [esc]")
        urwid.connect_signal(back_button, 'click', go_back_one_level)
        
        button_container = urwid.Columns([
            ('weight', 1, urwid.Text("")),
            ('pack', urwid.AttrMap(back_button, None, focus_map="menu_focus")),
            ('weight', 1, urwid.Text(""))
        ])
        
        view = urwid.Pile([
            urwid.Divider(),
            message,
            urwid.Divider(),
            button_container
        ])
        
        main.original_widget = apply_box_style(
            urwid.Filler(view, valign='middle'),
            title="Audit Log"
        )
        return
    
    # Categorize files by log level
    log_levels = {
        "debug": {"files": [], "total_size": 0, "last_updated": None},
        "info": {"files": [], "total_size": 0, "last_updated": None},
        "warning": {"files": [], "total_size": 0, "last_updated": None},
        "error": {"files": [], "total_size": 0, "last_updated": None},
        "critical": {"files": [], "total_size": 0, "last_updated": None},
        "other": {"files": [], "total_size": 0, "last_updated": None}
    }
    
    # Process log files
    for log_file in log_files:
        file_path = os.path.join(logs_dir, log_file)
        file_size = os.path.getsize(file_path)
        mod_time = os.path.getmtime(file_path)
        
        level_date_match = re.match(r'(\w+)\.(\d{8})\.log', log_file)
        
        if level_date_match:
            level, _ = level_date_match.groups()
            level = level.lower()
            
            if level in log_levels:
                log_levels[level]["files"].append(log_file)
                log_levels[level]["total_size"] += file_size
                
                if log_levels[level]["last_updated"] is None or mod_time > log_levels[level]["last_updated"]:
                    log_levels[level]["last_updated"] = mod_time
            else:
                log_levels["other"]["files"].append(log_file)
                log_levels["other"]["total_size"] += file_size
                
                if log_levels["other"]["last_updated"] is None or mod_time > log_levels["other"]["last_updated"]:
                    log_levels["other"]["last_updated"] = mod_time
        else:
            log_levels["other"]["files"].append(log_file)
            log_levels["other"]["total_size"] += file_size
            
            if log_levels["other"]["last_updated"] is None or mod_time > log_levels["other"]["last_updated"]:
                log_levels["other"]["last_updated"] = mod_time
    
    # Create grid header with weight-based columns (not fixed width)
    header = urwid.Columns([
        ('weight', 2, urwid.Text(('bold_title', "Log Level"))),
        ('weight', 1, urwid.Text(('bold_title', "Files"))),
        ('weight', 2, urwid.Text(('bold_title', "Size"))),
        ('weight', 2, urwid.Text(('bold_title', "Date"))),
        ('weight', 1, urwid.Text(('bold_title', "Time"))),
        ('weight', 2, urwid.Text(('bold_title', "About")))
    ])
    
    # Create header divider
    divider = urwid.Divider('─')

    # Add log level descriptions
    log_descriptions = {
        "debug": "Detailed diagnostic information for developers",
        "info": "General operational information",
        "warning": "Non-critical issues that should be reviewed",
        "error": "Problems affecting functionality",
        "critical": "Severe issues needing immediate action",
        "other": "Miscellaneous logs not fitting other categories"
}
    
    # Create rows for each log level
    rows = []
    for level, data in log_levels.items():
        if not data["files"]:
            continue  # Skip empty categories
        
        # Format file count
        file_count = len(data["files"])
        
        # Format total size
        total_size = data["total_size"]
        if total_size < 1024:
            size_str = f"{total_size} B"
        elif total_size < 1024 * 1024:
            size_str = f"{total_size/1024:.1f} KB"
        else:
            size_str = f"{total_size/(1024*1024):.1f} MB"
        
        # Format last updated date and time separately
        date_str = "N/A"
        time_str = "N/A"
        if data["last_updated"]:
            last_date = datetime.fromtimestamp(data["last_updated"])
            date_str = last_date.strftime('%d-%m-%Y')
            time_str = last_date.strftime('%H:%M')

        # Get the description for this log level
        description = log_descriptions.get(level, "")

        # Create row columns with the same weight distribution as header
        row_columns = urwid.Columns([
            ('weight', 2, urwid.Text(level.capitalize())),
            ('weight', 1, urwid.Text(str(file_count))),
            ('weight', 2, urwid.Text(size_str)),
            ('weight', 2, urwid.Text(date_str)),
            ('weight', 1, urwid.Text(time_str)),
            ('weight', 2, urwid.Text(description))
        ])
        
        # Make the row selectable
        row_btn = BatchRowButton(row_columns, level)
        urwid.connect_signal(row_btn, 'click', 
                           lambda button, lvl=level: show_log_files_by_level(lvl))
        
        rows.append(urwid.AttrMap(row_btn, None, focus_map="menu_focus"))
    
    # Combine header and rows
    grid = [
        header,
        divider
    ] + rows
    
    # Create scrollable list box
    list_walker = urwid.SimpleListWalker(grid)
    list_box = urwid.ListBox(list_walker)
    list_with_scrollbar = urwid.ScrollBar(list_box)
    content_box = urwid.BoxAdapter(list_with_scrollbar, 20)
    
    # Back button
    back_button = PlainButton("Back [esc]")
    urwid.connect_signal(back_button, 'click', go_back_one_level)
    
    button_container = urwid.Columns([
        ('weight', 1, urwid.Text("")),
        ('pack', urwid.AttrMap(back_button, None, focus_map="menu_focus")),
        ('weight', 1, urwid.Text(""))
    ])
    
    # Main view
    view = urwid.Pile([
        content_box,
        urwid.Divider(),
        button_container,
        urwid.Divider()
    ])
    
    # Update main widget
    main.original_widget = apply_box_style(
        urwid.Filler(view, valign='top'),
        title="Audit Log Categories"
    )

    def show_log_files_by_level(level):
        """Display log files of a specific level"""
        global current_menu, menu_stack
        
        # Update menu tracking
        if current_menu != f"audit_log_{level}":
            menu_stack.append(current_menu)
            current_menu = f"audit_log_{level}"
        
        logs_dir = os.path.join(os.getcwd(), 'logs')
        
        # Get log files for the specified level
        log_files = []
        try:
            import re
            for f in os.listdir(logs_dir):
                if os.path.isfile(os.path.join(logs_dir, f)) and (f.endswith('.log') or f.endswith('.txt')):
                    if level.lower() == "other":
                        # For "other" category, include files that don't match the pattern
                        if not re.match(r'(\w+)\.(\d{8})\.log', f) and f != "errors.log":
                            log_files.append(f)
                    else:
                        # Match files for the specific level
                        level_match = re.match(fr'{level}\.(\d{{8}})\.log', f)
                        if level_match:
                            log_files.append(f)
        except Exception as e:
            logger.error(f"Error listing log files: {e}")
        
        # Sort log files by modification time (newest first)
        log_files.sort(key=lambda f: os.path.getmtime(os.path.join(logs_dir, f)), reverse=True)
        
        # Create file list
        file_items = []
        for log_file in log_files:
            # Get modification time and file size for additional info
            file_path = os.path.join(logs_dir, log_file)
            mod_time = os.path.getmtime(file_path)
            file_size = os.path.getsize(file_path)
            
            # Format size nicely
            if file_size < 1024:
                size_str = f"{file_size} B"
            elif file_size < 1024 * 1024:
                size_str = f"{file_size/1024:.1f} KB"
            else:
                size_str = f"{file_size/(1024*1024):.1f} MB"
            
            # Parse filename to extract log level and date
            level_date_match = re.match(r'(\w+)\.(\d{8})\.log', log_file)
            
            if level_date_match:
                # New format: "level.YYYYMMDD.log"
                _, date_str = level_date_match.groups()
                
                # Convert YYYYMMDD to DD-MM-YYYY
                try:
                    year = date_str[0:4]
                    month = date_str[4:6]
                    day = date_str[6:8]
                    formatted_date = f"{day}-{month}-{year}"
                    
                    button_text = f"{level.capitalize()} {formatted_date} ({size_str})"
                except:
                    # Fallback if date parsing fails
                    button_text = f"{log_file} ({size_str})"
            else:
                # For other log files
                button_text = f"{log_file} ({size_str})"
            
            # Create button with file info
            button = PlainButton(button_text)
            urwid.connect_signal(button, 'click', 
                                 lambda button, path=file_path, name=log_file: view_log_file(path, name))
            
            # Add to list
            file_items.append(urwid.AttrMap(button, None, focus_map="menu_focus"))
            file_items.append(urwid.Divider())  # Space between items
        
        if not file_items:
            # Display message if no files found for this level
            file_items.append(urwid.Text(f"No {level} log files found."))
            file_items.append(urwid.Divider())
        
        # Create a ListBox with all log files
        list_walker = urwid.SimpleListWalker([urwid.Divider()] + file_items)
        list_box = urwid.ListBox(list_walker)
        scrollable_area = urwid.ScrollBar(list_box)
        content_box = urwid.BoxAdapter(scrollable_area, 20)
        
        # Back button
        back_button = PlainButton("Back [esc]")
        urwid.connect_signal(back_button, 'click', go_back_one_level)
        
        button_container = urwid.Columns([
            ('weight', 1, urwid.Text("")),
            ('pack', urwid.AttrMap(back_button, None, focus_map="menu_focus")),
            ('weight', 1, urwid.Text(""))
        ])
        
        view = urwid.Pile([
            content_box,
            urwid.Divider(),
            button_container,
            urwid.Divider()
        ])
        
        level_title = level.capitalize()
        main.original_widget = apply_box_style(
            urwid.Filler(view, valign='top', top=0, bottom=0),
            title=f"{level_title} Logs"
        )    

def view_log_file(file_path, file_name):
    """Display contents of a log file with improved formatting for JSON logs"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Create header with separate Module and Function columns
        header = urwid.Columns([
            ('weight', 1, urwid.Text(('bold_title', "Time"))),
            ('weight', 1, urwid.Text(('bold_title', "Module"))),
            ('weight', 2, urwid.Text(('bold_title', "Function"))),
            ('weight', 5, urwid.Text(('bold_title', "Message")))
        ])
        
        # Add header divider
        divider = urwid.Divider('─')
        
        # Process content to handle JSON log lines
        processed_lines = []
        for line in content.splitlines():
            try:
                # Try to parse as JSON
                log_entry = json.loads(line)
                
                # Extract the parts we want to display
                timestamp = log_entry.get("timestamp", "").split(" ")[1]  # Just take the time part
                module = log_entry.get('module', '')
                function = log_entry.get('function', '')
                level = log_entry.get("level", "").upper()
                message = log_entry.get("message", "")
                
                # Create a formatted line with separate module and function columns
                line_widget = urwid.Columns([
                    ('weight', 1, urwid.Text(timestamp)),
                    ('weight', 1, urwid.Text(module)),
                    ('weight', 2, urwid.Text(function)),
                    ('weight', 5, urwid.Text(message))
                ])
                
                processed_lines.append(line_widget)
            except json.JSONDecodeError:
                # If not JSON, keep the original line
                processed_lines.append(urwid.Text(line))
                
    except Exception as e:
        logger.error(f"Error reading log file {file_path}: {e}")
        processed_lines = [urwid.Text(f"Error reading log file: {str(e)}")]
    
    # Create a list walker with the header and all processed lines
    list_walker = urwid.SimpleListWalker([header, divider] + processed_lines)
    list_box = urwid.ListBox(list_walker)
    scrollable_area = urwid.ScrollBar(list_box)
    content_box = urwid.BoxAdapter(scrollable_area, 25)
    
    # Back button - returns to the log file list
    back_button = PlainButton("Back [esc]")
    urwid.connect_signal(back_button, 'click', go_back_one_level)
    
    button_container = urwid.Columns([
        ('weight', 1, urwid.Text("")),
        ('pack', urwid.AttrMap(back_button, None, focus_map="menu_focus")),
        ('weight', 1, urwid.Text(""))
    ])
    
    view = urwid.Pile([
        content_box,
        urwid.Divider(),
        button_container,
        urwid.Divider()
    ])
    
    main.original_widget = apply_box_style(
        urwid.Filler(view, valign='top', top=0, bottom=0),
        title=f"Log File: {file_name}"
    )

# Global reference to the main loop
_main_loop = None

def get_main_loop():
    """Get the global main loop reference"""
    global _main_loop
    return _main_loop

# Then modify your main loop initialization
try:
    _main_loop = urwid.MainLoop(
        top, 
        palette=[
        ("reversed", "standout", ""),
        ("menu_focus", "white", "dark red"),
        ("terminal_edit", "black", "light gray"), 
        ("terminal_bg", "white", "dark gray"),
        ("edit_unfocused", "black", "light gray"),
        ("edit_focused", "black", "light gray"),
        ("edit_cursor", "light gray", "light gray"),
        ("green_btn", "light green", "dark green"),
        ("blue_btn", "light blue", "dark blue"),
        ("red_btn", "light red", "dark red"),
        ("error_edit", "white", "dark red"),
        ("bold_title", "white,bold", ""),
        ("scrollbar", "black", "light gray"),
        ("cat_art", "light gray", ""),
        ("progress_bg", "black", "dark gray"),
        ("progress_fg", "white", "dark blue")
        ], 
        handle_mouse=True, 
        unhandled_input=global_keypress
    )
    
    _main_loop.run()
except Exception as e:
    logger.error(f"Error starting application UI: {e}", exc_info=True)
    import traceback
    print(f"Error starting application urwid: {e}")
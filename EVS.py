#!/usr/bin/env python3
# Email Verification Script
# Copyright (C) 2025 Kim Skov Rasmussen
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

import sys
import subprocess

# List required external dependencies (modules not included in the standard library)
required_dependencies = ["dns", "requests", "tabulate"]
missing_dependencies = []

for dep in required_dependencies:
    try:
        __import__(dep)
    except ImportError:
        missing_dependencies.append(dep)

if (missing_dependencies):
    print("Missing dependencies: " + ", ".join(missing_dependencies))
    choice = input("Do you want to install them? (Y/N): ")
    if choice.lower() in ["y", "yes"]:
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "--user", *missing_dependencies]
            )
            print("Dependencies installed successfully. Please restart the script.")
        except Exception as e:
            print("Error installing dependencies:", e)
    sys.exit(0)

# Continue with the rest of the script once all dependencies are present.
import os
import platform
import socket
import dns.resolver
import smtplib
import re
import requests
import csv
from datetime import datetime
import time
import imaplib
import poplib
import webbrowser
import configparser
from tabulate import tabulate
from concurrent.futures import ThreadPoolExecutor

# Name of the log file
LOG_FILE = "log.txt"

# List of known blacklisted domains (for demonstration)
BLACKLISTED_DOMAINS = {
    "blacklisted.com": ["Spamhaus", "Barracuda", "SpamCop"],
    "baddomain.net": ["Spamhaus", "SORBS"],
    "malicious.org": ["SpamCop", "Spamhaus"]
}

# --- Other Script Definitions ---

def clear_screen():
    # Check the operating system and use the appropriate command
    if platform.system() == "Windows":
        os.system('cls')  # Windows
    else:
        os.system('clear')  # Linux and macOS
# --- Help ---
  
def display_help():
    """Display custom help text."""
    help_command = (
        "\n"
        "Usage:\n"
        "----------------------------------------------------------------------\n"
        "  - Enter one or more email addresses separated by commas to check their validity.\n"
        "  - For example: test@example.com, user@domain.com\n"
        "\n"
        "Or Type:\n"
        "\n"
        "  - 'help' to display this help message.\n"
        "  - 'exit' to quit the program.\n"
        "  - 'show log' to display a simple list of logged emails and their validation status.\n"    
        "  - 'clear log' Delete all content from the log file.\n"    
        "  - 'log help' to display how the log works\n"
        "  - 'read more' to learn more about: Key Features and Functions, What to Expect and Use Cases\n"
        "  - 'clear' to clear the terminal window\n"        
        "\n"
    )
    print(help_command)
    
def display_log_help():
    """Display custom help text."""
    help_log = ( 
        "\n"
        "Log file details:\n"
        "----------------------------------------------------------------------\n"
        "  - All email validation checks are logged to `log.txt`.\n"
        "  - Each log entry is in CSV format and includes details such as:\n"
        "    • Timestamp of the check\n"
        "    • Email address and associated domain\n"
        "    • MX record and the port used for verification\n"
        "    • Disposable email status, SPF and DKIM results\n"
        "    • SMTP and VRFY outcomes, catch-all detection, and blacklist info\n"
        "    • Additional technical details like SMTP banner, MX IP, and IMAP/POP3 status\n"
        "  - Reviewing this file can help diagnose issues and confirm the results of the validation process.\n"
        "\n" 
        "Editing the EVS.INI file:\n"
        "\n" 
        "  - The EVS.INI file controls the display of columns in the log output.\n"
        "  - You can specify which columns to show or hide using the Show=Y or Show=N options.\n"
        "    • Show=Y 'Column Name':index will include the column in the display.\n"
        "    • Show=N 'Column Name':index will exclude the column from the display.\n"
        "  - The format for specifying each column is:\n"
        "    • Show=Y 'Column Name':index\n"
        "    • For example, Show=Y 'Timestamp':0 will display the timestamp in the log.\n"
        "  - Additionally, you can rename the column names in the EVS.INI file. To rename a column, simply change the text inside the quotes:\n"
        "    • For example, Show=Y 'Timestamp':0 can be renamed to Show=Y 'Time of Check':0.\n"
        "  - Editing the EVS.INI allows you to customize which details are logged, displayed, and even renamed to suit your preferences.\n"
        "\n"
    )
    print(help_log)
   
# --- Disposable and Blacklist Detection ---

def is_disposable_email(email):
    """Check if the email is from a disposable email provider."""
    disposable_domains = [
        "mailinator.com", "10minutemail.com", "tempmail.com", "temp-mail.org",
        "guerrillamail.com", "dispostable.com", "yopmail.com", "getnada.com", "tempinbox.com"
    ]
    domain = email.split('@')[1].lower()
    return domain in disposable_domains

def check_blacklists(email):
    """Check if the email's domain is blacklisted.
    Returns a comma-separated string of blacklist sites if found, otherwise 'Not Blacklisted'."""
    domain = email.split('@')[1].lower()
    if domain in BLACKLISTED_DOMAINS:
        return ", ".join(BLACKLISTED_DOMAINS[domain])
    else:
        return "Not Blacklisted"

# --- DNS and SMTP Functions ---

def get_mx_record(domain):
    """Get the MX records for a domain sorted by preference."""
    try:
        answers = dns.resolver.resolve(domain, 'MX', lifetime=10)  # Increase DNS resolution timeout
        return sorted(answers, key=lambda x: x.preference)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout, dns.resolver.NoNameservers) as e:
        print(f"DNS resolution error for {domain}: {e}")
        return None

def check_spf(domain):
    """Check for SPF record in domain's TXT records."""
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            if "v=spf1" in str(rdata):
                return "SPF Found"
        return "No SPF Record"
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return "No SPF Record"

def check_dkim(domain):
    """Check for DKIM TXT record in domain's DNS settings."""
    dkim_selector = "default"  # Common selector; adjust if needed
    dkim_domain = f"{dkim_selector}._domainkey.{domain}"
    try:
        answers = dns.resolver.resolve(dkim_domain, 'TXT')
        for rdata in answers:
            if "v=DKIM1" in str(rdata):
                return "DKIM Found"
        return "No DKIM Record"
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return "No DKIM Record"

def test_smtp_connection(server, port, email, retries=3):
    """Test SMTP connection to a server on a specific port by sending RCPT command, with retries.
       Uses a shorter timeout for port 25."""
    timeout = 10 if port == 25 else 20  # Increase SMTP connection timeout
    for attempt in range(retries):
        try:
            with smtplib.SMTP(server, port, timeout=timeout) as smtp:
                smtp.ehlo()
                smtp.mail("test@domain.com")
                code, _ = smtp.rcpt(email)
                if code == 250:
                    return True
        except Exception as e:
            print(f"SMTP connection error on attempt {attempt + 1} for {server}:{port} - {e}")
            time.sleep(2)  # Increase sleep duration between retries
            continue
    return False

def smtp_vrfy(server, port, email):
    """Attempt SMTP VRFY command to check if the email exists."""
    try:
        with smtplib.SMTP(server, port, timeout=10) as smtp:
            smtp.ehlo()
            code, msg = smtp.verify(email)
            if isinstance(msg, bytes):
                msg = msg.decode()
            return code, msg
    except Exception as e:
        return None, str(e)

# --- Additional Technical Details Functions ---

def get_smtp_banner(server):
    """Get the SMTP banner by trying HELLO and then EHLO commands, removing newlines."""
    try:
        with smtplib.SMTP(server, timeout=10) as smtp:
            banner = smtp.docmd("HELLO")
            if banner[0] == 250:
                result = banner[1].decode() if banner else "No banner"
            else:
                banner = smtp.ehlo()
                result = banner[1].decode() if banner else "No banner"
            return result.replace("\n", " ").strip()
    except Exception as e:
        return str(e)

def get_mx_ip(server):
    """Get the IP address of the MX server."""
    try:
        ip = socket.gethostbyname(server)
        return ip
    except socket.gaierror:
        return "Unknown IP"

# --- New Protocol Check Functions (IMAP/POP3) ---

def check_imap_ssl(server):
    """Check if the server supports IMAP over SSL on port 993."""
    try:
        imap = imaplib.IMAP4_SSL(server, 993, timeout=5)
        banner = imap.welcome.decode() if isinstance(imap.welcome, bytes) else imap.welcome
        imap.logout()
        return "Available", banner.replace("\n", " ").strip()
    except Exception as e:
        return "Not available", str(e)

def check_pop3_ssl(server):
    """Check if the server supports POP3 over SSL on port 995."""
    try:
        pop = poplib.POP3_SSL(server, 995, timeout=5)
        banner = pop.getwelcome().decode() if isinstance(pop.getwelcome(), bytes) else pop.getwelcome()
        pop.quit()
        return "Available", banner.replace("\n", " ").strip()
    except Exception as e:
        return "Not available", str(e)

# --- Logging Functions ---
# Log Order:
# Timestamp, Email Address, Domain, MX Record, Used Port, Disposable Email, SPF Status, DKIM Status,
# Catch-all Email, SMTP Result, SMTP VRFY Result, Blacklist Info, MX Preferences, SMTP Banner, MX IP,
# Error Message

def sanitize_log_entry(value):
    """Sanitize log entry to prevent CSV injection and remove problematic characters"""
    if value is None:
        return ""
    
    # Convert to string and clean up
    value = str(value)
    value = value.replace('\n', ' ').replace('\r', ' ')
    value = value.replace(',', ';')  # Replace commas with semicolons
    value = re.sub(r'\s+', ' ', value)  # Replace multiple spaces with single space
    return value.strip()

def log_email_check(email, mx_record, spf_status, dkim_status, smtp_result, used_port, domain,
                    error_message="", catch_all_email="", disposable_status="",
                    smtp_vrfy_result="", blacklist_info="", mx_preferences="", smtp_banner="", mx_ip="",
                    imap_status="", imap_banner="", pop3_status="", pop3_banner=""):
    # Sanitize all fields before logging
    log_entry = [
        sanitize_log_entry(datetime.now().strftime("%d-%m-%y %H:%M")),  # Timestamp
        sanitize_log_entry(email),
        sanitize_log_entry(domain),
        sanitize_log_entry(mx_record),
        sanitize_log_entry(used_port),
        sanitize_log_entry(disposable_status),
        sanitize_log_entry(spf_status),
        sanitize_log_entry(dkim_status),
        sanitize_log_entry(catch_all_email),
        sanitize_log_entry(smtp_result),
        sanitize_log_entry(smtp_vrfy_result),
        sanitize_log_entry(blacklist_info),
        sanitize_log_entry(mx_preferences),
        sanitize_log_entry(smtp_banner),
        sanitize_log_entry(mx_ip),
        sanitize_log_entry(error_message),
        sanitize_log_entry(imap_status),
        sanitize_log_entry(imap_banner),
        sanitize_log_entry(pop3_status),
        sanitize_log_entry(pop3_banner),
        1  # Search Counter
    ]
    
    # Define standard header row
    header_row = [
        "Timestamp", "Email Address", "Domain", "MX Record", "Used Port", "Disposable Email",
        "SPF Status", "DKIM Status", "Catch-all Email", "SMTP Result", "SMTP VRFY Result",
        "Blacklist Info", "MX Preferences", "SMTP Banner", "MX IP", "Error Message",
        "IMAP Status", "IMAP Banner", "POP3 Status", "POP3 Banner", "Search Counter"
    ]
    
    rows = []
    updated = False
    header_written = False

    # Check if file exists and process existing entries
    if os.path.isfile(LOG_FILE):
        with open(LOG_FILE, mode="r", newline="") as file:
            reader = csv.reader(file)
            rows = list(reader)
            if rows and rows[0] == header_row:
                header_written = True

            # Process rows to find and update existing email
            for i, row in enumerate(rows):
                if row and row[1] == email:
                    # Update all fields while preserving structure
                    row[0:20] = log_entry[0:20]  # Update all fields except counter
                    row[20] = str(int(row[20]) + 1)  # Increment counter
                    updated = True
                    break

    # If email was not found, append new log entry
    if not updated:
        rows.append(log_entry)
    else:
        # Move updated entry to bottom
        updated_row = rows.pop(i)
        rows.append(updated_row)

    # Write all entries back to file
    with open(LOG_FILE, mode="w", newline="") as file:
        writer = csv.writer(file)
        if not header_written:
            writer.writerow(header_row)
        writer.writerows(rows)

def check_existing_log_for_domain(domain):
    """Check log.txt for a previous check for the domain and return a valid port if found."""
    if not os.path.isfile(LOG_FILE):
        return None
    with open(LOG_FILE, mode="r", newline="") as file:
        reader = csv.reader(file)
        try:
            next(reader)  # Skip header row
        except StopIteration:
            return None
        for row in reader:
            if len(row) >= 8:
                try:
                    if row[2].strip().lower() == domain.strip().lower():
                        port_value = row[4].strip()
                        if port_value and port_value.upper() != "N/A":
                            return port_value
                except IndexError:
                    continue
    return None

# --- Email Validation Functions ---

def check_smtp_with_port(domain, email, port):
    """Check the SMTP server with a specific port."""
    mx_records = get_mx_record(domain)
    if mx_records:
        for mx in mx_records:
            server = str(mx.exchange).rstrip('.')
            if test_smtp_connection(server, port, email):
                return "Email likely exists"
    return "Could not verify email"

def validate_email(email):
    """Validate the email address by checking MX records, SPF, DKIM, SMTP response,
    disposable status, deeper SMTP VRFY, blacklist info, and IMAP/POP3 support."""
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        log_email_check(email, "Invalid Format", "N/A", "N/A", "Invalid Email Format",
                        "N/A", "N/A", error_message="Invalid email format", blacklist_info=check_blacklists(email))
        return "Invalid email format."
    
    domain = email.split('@')[1]
    disposable_status = "Disposable" if is_disposable_email(email) else "Not Disposable"
    blacklist_info = check_blacklists(email)
    
    smtp_vrfy_result = ""
    catch_all_email = ""
    mx_preferences = ""
    smtp_banner = ""
    mx_ip = ""
    
    # Check for cached valid port
    existing_port = check_existing_log_for_domain(domain)
    if existing_port:
        print(f"Using cached port {existing_port} for domain {domain}.")
        smtp_result = check_smtp_with_port(domain, email, int(existing_port))
        code, vrfy_msg = smtp_vrfy(str(get_mx_record(domain)[0].exchange).rstrip('.'),
                                   int(existing_port), email)
        smtp_vrfy_result = "Verified" if code == 250 else "Not Verified"
        if smtp_result == "Email likely exists":
            fake_email = f"nonexistent{int(time.time())}@{domain}"
            if test_smtp_connection(str(get_mx_record(domain)[0].exchange).rstrip('.'),
                                      int(existing_port), fake_email):
                smtp_result = "Email likely exists"
                catch_all_email = fake_email
                print(f"Catch-all detected: {fake_email} (email likely exists)")
        mx_preferences = ", ".join([str(mx.preference) for mx in get_mx_record(domain)])
        smtp_banner = get_smtp_banner(str(get_mx_record(domain)[0].exchange).rstrip('.'))
        mx_ip = get_mx_ip(str(get_mx_record(domain)[0].exchange).rstrip('.'))
        
        log_email_check(email, "MX Found", check_spf(domain), check_dkim(domain),
                        smtp_result, existing_port, domain, error_message="",
                        catch_all_email=catch_all_email, disposable_status=disposable_status,
                        smtp_vrfy_result=smtp_vrfy_result, blacklist_info=blacklist_info,
                        mx_preferences=mx_preferences, smtp_banner=smtp_banner, mx_ip=mx_ip)
        return smtp_result

    print(f"Checking MX records for {domain}...")
    mx_records = get_mx_record(domain)
    if not mx_records:
        log_email_check(email, "No MX Records", "N/A", "N/A", "Could not verify email", "N/A", domain,
                        error_message="No MX records found", blacklist_info=blacklist_info, disposable_status=disposable_status,
                        smtp_vrfy_result="N/A", mx_preferences="N/A", smtp_banner="N/A", mx_ip="N/A")
        return "This domain cannot receive emails (no MX records)."
    
    primary_mx = str(mx_records[0].exchange).rstrip('.')
    print(f"Primary MX for {domain} is {primary_mx}.")
    
    spf_status = check_spf(domain)
    dkim_status = check_dkim(domain)
    
    smtp_result = "Could not verify email"
    used_port = "N/A"
    error_message = ""
    
    # Try ports 25, 587, and 465
    for port in [25, 587, 465]:
        print(f"Testing {domain} on port {port}...")
        if test_smtp_connection(primary_mx, port, email):
            smtp_result = "Email likely exists"
            used_port = port
            break
    if smtp_result == "Email likely exists":
        fake_email = f"nonexistent{int(time.time())}@{domain}"
        if test_smtp_connection(primary_mx, used_port, fake_email):
            smtp_result = "Email likely exists"
            catch_all_email = fake_email
            print(f"Catch-all detected: {fake_email} (email likely exists)")
    else:
        error_message = "SMTP check failed. Could not verify email."
    
    code, vrfy_msg = smtp_vrfy(primary_mx, used_port if used_port != "N/A" else 25, email)
    smtp_vrfy_result = "Verified" if code == 250 else "Not Verified"
    
    mx_preferences = ", ".join([str(mx.preference) for mx in mx_records])
    smtp_banner = get_smtp_banner(primary_mx)
    mx_ip = get_mx_ip(primary_mx)
    imap_status, imap_banner = check_imap_ssl(primary_mx)
    pop3_status, pop3_banner = check_pop3_ssl(primary_mx)
    
    log_email_check(email, primary_mx, spf_status, dkim_status, smtp_result, used_port, domain,
                    error_message, catch_all_email, disposable_status, smtp_vrfy_result, blacklist_info,
                    mx_preferences, smtp_banner, mx_ip, imap_status, imap_banner, pop3_status, pop3_banner)
    return smtp_result

def validate_emails(emails):
    """Validate multiple email addresses in parallel."""
    with ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(validate_email, emails))
    return results

# --- Show log---   

def load_selected_columns(ini_file="EVS.INI"):
    selected_columns = {}

    try:
        with open(ini_file, "r") as file:
            lines = file.readlines()

            for line in lines:
                line = line.strip()

                # Skip empty lines or comments
                if not line or line.startswith(";"):
                    continue

                # Look for lines in the format: Show=[Y/N] "Column Name":index
                if 'Show' in line:
                    parts = line.split('"')
                    if len(parts) >= 3:
                        show_value = parts[0].split('=')[1].strip()  # Y or N
                        column_name = parts[1].strip()
                        index = int(parts[2].replace(":", "").strip())

                        # Only add if 'Show=Y'
                        if show_value == "Y":
                            selected_columns[column_name] = index
                            # Debugging the column name and index
                            # print(f"Selected column: {column_name} with index: {index}")

    except Exception as e:
        print(f"Error reading {ini_file}: {e}")

    return selected_columns

def show_log(file_path="log.txt", ini_file="EVS.INI"):
    selected_columns = load_selected_columns(ini_file)

    # If no columns are selected, exit early
    if not selected_columns:
        print("No columns selected to display.\n")
        return
        
    try:
        with open(file_path, "r") as log_file:
            lines = log_file.readlines()

            if not lines:
                print("Log file is empty.\n")
                return

            print("\nEmail Validation Summary:")
            print("======================================================================")

            # Split header from the first line and check the number of columns
            header = lines[0].strip().split(",")
            num_columns = len(header)

            # Filter selected headers and validate against the actual number of columns in the header
            selected_header = [
                key for key in selected_columns.keys()
                if selected_columns[key] < num_columns  # Validate the index is within bounds
            ]
            if not selected_header:
                print("No valid columns to display after validation.\n")
                return

            # Extract data rows
            table_data = []
            for line in lines[1:]:
                parts = line.strip().split(",")
                row = []
                for key in selected_header:
                    index = selected_columns[key]
                    value = parts[index] if index < len(parts) else ""

                    # Convert "Catch-all Email" values to Yes/No
                    if key == "Catch-all Email":
                        value = "Yes" if value.strip() else "No"

                    row.append(value)
                table_data.append(row)

            # Print table using tabulate
            print(tabulate(table_data, headers=selected_header, tablefmt="github", numalign="left"))

    except FileNotFoundError:
        print("Log file not found.\n")
    except Exception as e:
        print(f"Error reading log file: {e}\n")
 
# --- Clear log---        
def clear_log():
    # Open the log file in write mode and truncate it (clear its content)
    with open("log.txt", "w") as log_file:
        log_file.truncate(0)  # Truncate the file to 0 length, effectively clearing it
    print("Log cleared!")  # Print confirmation message

# --- Startup Message ---

START_MESSAGE = (
"======================================================================\n"
    "Email Verification Script - Version 1.0\n"
    "Copyright (C) 2025 Kim Skov Rasmussen\n"
    "Licensed under GNU General Public License v3.0\n"  
    "This software is provided as is, without any warranties.\n"  
    "Use at your own risk. For educational purposes only.\n"
    "\n"
    "Type 'help' to view a list of commands and usage instructions.\n"
"======================================================================\n"
)

# --- Exit Message ---

EXIT_MESSAGE = (
"======================================================================\n"
    "Email Verification Script has exited.\n"
    "Thank you for using this tool.\n"  
    "Remember: This software is provided as is under GNU GPL v3.\n"
"======================================================================\n"
)

# --- Main Loop ---
def main():
    clear_screen()  # Clear the terminal window before displaying message
    print(START_MESSAGE)  # Display your custom startup message

    while True:
        user_input = input("Command> ").strip()

        # Handle special commands first
        if user_input.lower() == "exit":
            clear_screen()
            print(EXIT_MESSAGE)  # Display exit message
            break

        elif user_input.lower() == "help":
            display_help()  # Call the function to display help
            continue
            
        elif user_input.lower() == "log help":
            display_log_help()  # Call the function to display log help
            continue

        elif user_input.lower() == "show log":
            show_log()  # Calls the function to display log summary
            continue

        elif user_input.lower() == "read more":
            # Construct the file path and open it in the browser
            file_path = os.path.join(os.getcwd(), "documentation", "ReadMe.txt")
            webbrowser.open(file_path)
            continue
            
        elif user_input.lower() == "clear log":
            clear_log()  # Calls the function to clear log.txt
            continue
            
        elif user_input.lower() == "clear":
            clear_screen()  # Clear the terminal window
            continue

        # Split input by commas and remove empty spaces
        emails = [email.strip() for email in user_input.split(",") if email.strip()]

        # Check if the input contains valid email(s)
        if any("@" in email and "." in email for email in emails):  
            results = validate_emails(emails)
            for email, result in zip(emails, results):
                print(f"{email}: {result}\n")
            continue  # Skip "Unknown command" check

        # If input is neither a known command nor a valid email, show an error
        print("Unknown command. Type 'help' for available commands.")

if __name__ == "__main__":
    main()
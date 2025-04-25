[![CodeQL Advanced](https://github.com/Ranrar/EVS/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/Ranrar/EVS/actions/workflows/codeql.yml) [![Microsoft Defender For DevOps](https://github.com/Ranrar/EVS/actions/workflows/defender-for-devops.yml/badge.svg)](https://github.com/Ranrar/EVS/actions/workflows/defender-for-devops.yml)

# Email Verification Script

This Python-based email verification script is designed to help you 
validate email addresses by analyzing various technical aspects of 
email systems. It performs an in-depth assessment to determine whether 
an email address is likely valid, invalid, or problematic, logging the 
results for future reference. While the tool provides valuable insights 
into email address validity, it's important to note that due to the 
complex and dynamic nature of email systems, it is never 100% accurate. 
<br>
</br>
This script is a robust internal validation tool and can offer insights 
into the technical setup of email addresses and domains. However, it 
should not be solely relied upon for verifying whether an email address 
is actively in use, especially for critical applications. To ensure 
higher accuracy, it's recommended to use this tool alongside other 
verification methods.

![EVS-menu](https://github.com/user-attachments/assets/253788b2-c2a5-4329-968f-302a17fe1321)

*Even though it is made on [urwid](https://github.com/urwid/urwid), it still works with limited functionality in Windows*


## Core Features

1. Email Format Validation:
   The script first checks whether the email address adheres to a 
   standard format (e.g., user@domain.com). Invalid emails are logged 
   with an error message.

2. Domain Checks:
   - MX Records: Verifies whether the domain associated with the email 
     has valid MX (Mail Exchange) records, indicating that it is capable 
     of receiving emails.
   - Disposable Email Detection: Checks if the email comes from a known 
     disposable email provider (e.g., mailinator.com, tempmail.com), 
     typically used for temporary emails.
   - Blacklist Checks: Looks up the domain in a predefined list of 
     blacklisted domains, which could indicate potential spam or 
     malicious activity.

3. SPF and DKIM Validation:
   - SPF (Sender Policy Framework): Checks if the domain has a valid SPF 
     record, helping verify that the email was sent from a trusted server.
   - DKIM (DomainKeys Identified Mail): Checks for DKIM records, which 
     verify the authenticity of the email's sender and prevent email 
     tampering.

4. SMTP Checks:
   - SMTP Connection Test: Attempts to connect to the SMTP server for 
     the domain on multiple ports (25, 587, 465) to see if the email 
     server is responsive and capable of handling the email address.
   - SMTP VRFY Command: Tries to verify whether the email address exists 
     on the mail server. However, many servers have this command disabled, 
     meaning this check may not always be accurate.

5. Catch-All Email Detection:
   - Detects if a domain is configured with a catch-all email address 
     (i.e., it accepts all emails for any address on that domain), using 
     a fake email address.

6. IMAP and POP3 SSL Checks:
   - Tests if the domain's mail server supports secure IMAP and POP3 
     connections on common SSL ports (993 for IMAP, 995 for POP3), 
     providing clues about the server's configuration and security.


## Advanced Features

7. Confidence Scoring System:
   - Each validation includes a detailed confidence score (0-100) that evaluates email validity
   - Scoring levels include: Very High (90-100), High (70-89), Medium (50-69), Low (30-49), Very Low (0-29)
   - Customizable scoring weights for different validation aspects

8. Batch Processing:
   - Import and validate lists of email addresses from external files
   - Track batch processing with detailed statistics (total emails, success rate, failures)
   - Store batch validation history with timestamps and settings snapshots
   - Review batch results with comprehensive reporting

9. Logging and Database Storage:
   - All validation results stored in SQLite database with complete browsing capabilities
   - Interactive record viewer with "Show All" and "Custom Filter" views
   - Filter records by date range, domain, confidence level, or email text
   - Column visibility options and sorting for personalized data viewing
   - Access logs via GUI interface or 'show log' commands

10. Settings Management:
    - Configure validation parameters and scoring weights
    - Customize confidence thresholds and validation behavior
    - Adjust performance settings for different environments
    - Note: The Settings menu UI exists but is not yet fully functional

11. Cross-Platform Terminal Interface:
    - Compatible with Windows, macOS, and Linux
    - Unified command interface across platforms
    - Terminal UI components for interactive operation

12. Comprehensive Export System:
    - Multiple filtering options: Date Range, Batch, Domain, Confidence Level
    - Field category selection (Metadata, Core, Security, Technical, Protocol)
    - CSV and JSON export formats supported
    - Customizable filenames with relevant metadata
   
## Technical Implementation

13. Performance Optimization:
    - Smart TTL caching system for DNS and lookup operations
    - Configurable cache settings per operation type
    - Performance monitoring with execution time tracking
    - Rate limiting to prevent being blocked by email servers

14. Domain Protection System:
    - Temporary blocking of domains that consistently reject connection attempts
    - Automatic cooldown periods with configurable duration
    - Protection against getting blacklisted by email servers

15. Advanced Rate Limiting:
    - Per-nameserver tracking using sliding window algorithm
    - Separate rate limits for different operation types
    - Automatic throttling to prevent server blocking

16. Nameserver Rotation and Failover:
    - Automatic rotation through multiple DNS nameservers
    - Smart failover when servers are unresponsive
    - Improved resilience for DNS operations

17. Resource Management:
    - Graceful shutdown process that properly closes connections
    - SMTP connection pooling for improved performance
    - Automatic cleanup of cached resources
    - Memory optimization for long-running processes

18. Error Handling and Reporting:
    - Detailed error categorization for all operations
    - Contextual error reporting with suggested remediation
    - User-friendly error messages with specific details
    - Success dialogs with operation statistics

19. Dynamic DNS Configuration:
    - Nameserver health monitoring and automatic disabling of unresponsive servers
    - Custom resolver timeouts with configurable settings
    - Parallel DNS query support for performance-critical operations
    - Adaptive timeout adjustments based on server response patterns

## What to Expect

1. Accuracy Limitations:
   - No Guarantees: The accuracy of email verification is never 100%. 
     Some mail servers may block commands (like VRFY or RCPT), making it 
     impossible to verify the existence of an email address. Anti-spam 
     measures could also interfere with the process.
   - Catch-All Detection: Even if an email doesn't explicitly exist, it 
     could still be accepted if the domain has a catch-all email configured.
   - Blacklist Information: The blacklist check relies on a predefined 
     list and may not catch all blacklisted domains.

2. Dynamic Email Systems:
   - Email server configurations can change frequently, and the script 
     does not guarantee real-time accuracy. It's recommended to verify 
     email addresses through multiple sources for precise accuracy.

3. Performance Considerations:
   - Validation time can vary significantly based on server response time,
     network conditions, and security measures in place.
   - The tool tracks and displays validation time for each email check.
   
## Use Cases for Internal Use

This email verification tool can be used internally for various purposes, 
including:

1. Email List Cleaning:
   - Reduces bounce rates and improves deliverability by ensuring you're 
     sending emails to valid addresses for marketing campaigns, mailing 
     lists, or CRM systems.

2. Security Audits:
   - Checks if an organization's email servers are properly configured 
     with SPF, DKIM, and MX records, helping prevent phishing and spoofing 
     attacks.

3. Spam Prevention:
   - Filters out potentially malicious or spam-related addresses by 
     checking disposable or blacklisted domains.

4. Catch-All Identification:
   - Identifies catch-all email configurations to determine if a domain 
     accepts all emails, or if more granular checks are required.

5. Compliance and Reporting:
   - Maintains a database log of all email validation attempts for auditing email 
     systems and ensuring compliance with certain regulations or internal 
     standards.

6. Performance Monitoring:
   - Tracks validation time for different email providers, helping you identify
     slow or problematic servers that might affect your email operations

## Command Reference

The script supports several commands:

- 'help'      - Display help message
- 'show log'  - Display email validation history with results
- 'show log all' - Display all email records including batch records
- 'show batch' - List all batches and prompt for a batch ID to view
- 'show batch <ID>' - Display all records from a specific batch directly
- 'clear log' - Delete all non-batch validation history
- 'clear log all' - Delete ALL validation history including batch records
- 'clear batch' - Delete a specific batch and its records
- 'settings'  - Not working yet
- 'clear'     - Clear the terminal screen
- 'read more' - Open the detailed documentation in your browser
- 'who am i'  - Display current user information
- 'refresh'   - Refresh database connection and clear cache
- 'debug log' - Show raw database records for debugging
- 'exit'      - Return to main menu

You can also enter one or more email addresses separated by commas to check their validity.
For example: test@example.com, user@domain.com

## Changelog

### Version 0.5.1 (02-04-2025)
- **Additions:**

- **Improvements:**
  - Enhanced database connection handling with auto-recovery mechanisms
  - Enhanced signal disconnection system to prevent memory leaks during navigation
  - Added graceful cleanup during application exit for proper resource management

- **Bug Fixes:**
  - Fixed issue where database connections weren't properly released after validation operations
  - Fixed signal disconnection issues when navigating between screens

- **Security Updates:**
- fixed when no information was logget from Try-Except-Pass

### Version 0.5 (29-03-2025)
- **Additions:**
  - Added audit log viewer with organized file sorting and detailed log viewing
  - Added export formats selection (CSV and JSON)
  - Added customization for confidence thresholds and validation behavior
  - Added support for detailed error categorization in validation results
  - Added log archive organization with month-based folder structure

- **Improvements:**
  - Improved batch progress tracking with live status updates and detailed progress information
  - Enhanced filter system for viewing records with multiple criteria
  - UI improvements with consistent navigation, styling, and box design
  - Better error handling and user feedback throughout the application
  - Added improved error containment to prevent sensitive information disclosure

- **Bug Fixes:**
  - Addressed error handling in batch processing operations with better feedback

- **Security Updates:**
  - Improved error containment to prevent sensitive information disclosure
  - Enhanced nameserver rotation and failover for improved resilience 

### Version 0.4 (15-03-2025)
- **Additions:**
  - Added database state refresh capability via `refresh` command in terminal mode
  - Implemented batch history view with success rate metrics
  - Added batch validation cancellation capability

- **Improvements:**
  - Improved multi-threading for parallel email validation
  - Enhanced validation record viewing with tabulated display
  - Optimized terminal history display with memory leak prevention

- **Bug Fixes:**
  - Fixed memory leaks in terminal history display
  - Fixed inconsistent UI state during batch cancellation operations

- **Security Updates:**
  - Added confirmation requirements for destructive database operations
  - Implemented rate limiting for DNS and SMTP operations to prevent server blocking
  - Added domain protection system to prevent getting blacklisted by email servers

### Version 0.3 (01-03-2025)
- **Additions:**
  - Added disposable email detection
  - Implemented domain blacklist checking
  - Added IMAP/POP3 availability checking
  - Implemented connection pooling for SMTP operations to improve performance

- **Improvements:**
  - Enhanced validation algorithm with confidence scoring
  - Improved terminal output formatting

- **Bug Fixes:**
  - Corrected validation scoring for domains with catch-all configurations

- **Security Updates:**
  - Implemented application state tracking system to detect and recover from abnormal terminations

### Version 0.2 (15-02-2025)
- **Additions:**
  - Initial batch processing capability
  - Added basic email format validation
  - Implemented simple terminal UI for interactive operation
  - Added result storage in SQLite database
  - Created initial configuration system

- **Improvements:**
  - None in this release

- **Bug Fixes:**
  - None in this release

- **Security Updates:**
  - None in this release

### Version 0.1 (01-02-2025)
- **Additions:**
  - Initial release
  - Basic email validation functionality
  - Command-line interface
  - Core validation engine
  - Simple logging system

- **Improvements:**
  - None in this release

- **Bug Fixes:**
  - None in this release

- **Security Updates:**
  - None in this release

## Future Updates

The following features are planned for upcoming releases:

1. Full Settings Menu Implementation:
   - Complete GUI settings interface with working save/apply functionality
   - Profile-based configurations for different validation scenarios
   - Import/export of configuration profiles

2. Background Processing Enhancements:
   - Fully asynchronous batch processing
   - Pause/resume functionality for long-running jobs

3. Database Encryption

4. Enhanced Statistics and Reporting

5. Extended Command System:
   - Additional command options and parameters
   - Command aliases for common operations

6. API Integration

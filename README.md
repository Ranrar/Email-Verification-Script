# Email Verification Script

A sophisticated Python-based email verification tool that performs comprehensive technical validation of email addresses through multiple verification methods. This script emphasizes responsible usage through built-in rate limiting and extensive logging capabilities.

## Core Features

### Smart Validation System
- **Format validation** using regex patterns
- **MX record verification** with DNS resolution
- **Multi-layer validation** with caching support
- **Built-in rate limiting** to prevent server abuse

### Security Checks
- **SPF (Sender Policy Framework) verification**
- **DKIM (DomainKeys Identified Mail) validation**
- **Domain blacklist checking**
- **Disposable email detection**

### Advanced Server Testing
- **SMTP connection testing** with support for ports 25, 587, and 465
- **Catch-all email detection**
- **SMTP VRFY command support**
- **IMAP/POP3 SSL verification** on ports 993 and 995

### Performance Optimizations
- **Connection pooling** with `SMTPConnectionPool`
- **TTL-based caching system**
- **Thread pool** for parallel email validation
- **Configurable rate limiting parameters**

## Responsible Usage Guidelines

### Rate Limiting Considerations
- Automatic rate limiting to prevent server abuse
- Configurable limits through `config.py`
- Built-in delays between retries for failed connections
- Sliding window rate limiting for SMTP operations

### Best Practices
- Configure appropriate rate limits
- Monitor server responses closely
- Implement gradual backoff for failed attempts
- Utilize connection pooling and caching
- Ensure proper error handling and logging

## Logging and Monitoring

### Comprehensive Logging
- Timestamp and unique ID for each check
- Technical details (MX records, IP addresses, ports)
- Security status (SPF, DKIM, blacklist results)
- Protocol support (SMTP, IMAP, POP3)
- Detailed error messages and validation results

### Log Management
- Logs available in CSV format for easy analysis
- Configurable column visibility
- Built-in functions for log viewing and clearing
- Support for log rotation and archiving

## Limitations and Considerations
- Server configurations may block verification attempts
- Catch-all domains can produce false positives
- The dynamic nature of email systems affects overall reliability
- Rate limiting may impact validation speed
- Some servers block SMTP verification commands
- Network conditions can impact results
- Always respect server policies and be mindful of automated query patterns
- Consider implementing IP rotation for large volumes

## Usage Scenarios

### Email List Maintenance
- Bulk validation with integrated rate limiting
- Historical validation tracking
- Format and domain verification to reduce bounce rates and improve deliverability

### Security Auditing
- Verify SPF/DKIM configurations
- Monitor domain blacklists
- Confirm proper server policies to prevent phishing and spoofing attacks

### System Integration
- API-ready implementation with configurable validation rules
- Extensive logging for compliance
- Easily integrated into systems for automated email validation and monitoring

## License

This project is licensed under the **GNU General Public License v3.0**.

## Note
This tool should be used responsibly and in compliance with email server policies and regulations. Always monitor and adjust rate limiting settings based on target server responses and policies.

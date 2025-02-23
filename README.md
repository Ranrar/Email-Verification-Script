# Email Verification Script

A sophisticated Python-based email verification tool that performs comprehensive technical validation of email addresses through multiple verification methods. This script emphasizes responsible usage through built-in rate limiting and extensive logging capabilities.

## Core Features

### Smart Validation System
- **Format validation** using regex patterns
- **MX record verification** with DNS resolution
- **Multi-layer validation approach** with caching support
- **Built-in rate limiting** to prevent server abuse

### Security Checks
- **SPF (Sender Policy Framework) verification**
- **DKIM (DomainKeys Identified Mail) validation**
- **Domain blacklist checking**
- **Disposable email detection**

### Advanced Server Testing
- **SMTP connection testing** with multiple port support (25, 587, 465)
- **Catch-all email detection**
- **SMTP VRFY command support**
- **IMAP/POP3 SSL verification** (ports 993/995)

### Performance Optimizations
- **Connection pooling** with `SMTPConnectionPool`
- **TTL-based caching system**
- **Thread pool** for parallel email validation
- **Configurable rate limiting parameters**

## Core Functions

This script performs email format validation, MX record verification, SPF and DKIM checks, SMTP connection testing, and more. It ensures comprehensive email validation through multiple layers of checks and optimizations.

## Responsible Usage Guidelines

### Rate Limiting Considerations
- The script implements **automatic rate limiting** to prevent server abuse
- **Configurable limits** through `config.py`
- **Built-in delays** between retries for failed connections
- **Sliding window rate limiting** for SMTP operations

### Best Practices
- Configure appropriate rate limits
- Monitor server responses
- Implement gradual backoff for failed attempts
- Use connection pooling and enable caching
- Implement proper error handling and logging

## Logging and Monitoring

### Comprehensive Logging System
- **Timestamp and unique ID** for each check
- **Technical details** (MX records, IP addresses, ports)
- **Security status** (SPF, DKIM, blacklist results)
- **Protocol support** (SMTP, IMAP, POP3)
- **Error messages and validation results**

### Log Management
- **CSV format** for easy analysis
- **Configurable column visibility**
- Built-in log viewing and clearing functions
- Support for log rotation and archiving

## Limitations and Considerations

### Accuracy Constraints
- Server configurations may block verification attempts
- Catch-all domains can produce false positives
- The dynamic nature of email systems affects reliability
- Rate limiting may impact validation speed
- Some servers block SMTP verification commands

### Technical Limitations
- Rate limiting may affect validation speed
- Some servers block SMTP verification commands
- Network conditions can impact results
- Respect server policies and restrictions
- Be mindful of automated query patterns
- Consider implementing IP rotation for large volumes

## Usage Scenarios

### Email List Maintenance
- Use this tool for bulk validation with rate limiting
- Historical validation tracking
- Format and domain verification
- Helps reduce bounce rates and improve deliverability for marketing campaigns, mailing lists, or CRM systems

### Security Auditing
- Check SPF/DKIM configuration
- Monitor blacklists
- Verify server policies
- Helps ensure email servers are properly configured, preventing phishing and spoofing attacks

### System Integration
- API-ready implementation with configurable validation rules and extensive logging for compliance
- Can be integrated into various systems for automated email validation and monitoring

## License

This project is licensed under the **GNU General Public License v3.0**.

## Note

This tool should be used responsibly and in compliance with email server policies and regulations. Always monitor and adjust rate limiting settings based on target server responses and policies.

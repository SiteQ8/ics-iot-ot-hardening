# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | ✅ Current         |
| 1.x.x   | ⚠️ Critical fixes  |
| < 1.0   | ❌ Unsupported     |

## Reporting a Vulnerability

If you discover a security vulnerability in this framework, please report it responsibly:

1. **DO NOT** open a public GitHub issue for security vulnerabilities
2. Email: [site@hotmail.com](mailto:site@hotmail.com) with subject "SECURITY: [Brief Description]"
3. Include: vulnerability description, reproduction steps, potential impact, and suggested fix
4. You will receive an acknowledgment within 48 hours
5. We will work with you to understand and address the issue

## Disclaimer

This framework provides security tools for authorized testing and hardening of ICS/OT environments only. Always:
- Obtain written authorization before scanning any network
- Test in development/lab environments before production deployment
- Follow your organization's change management procedures
- Ensure all testing complies with local laws and regulations

## Security Best Practices

When using this framework:
- Run with minimum required privileges
- Store scan reports securely (they contain sensitive network data)
- Use environment variables for credentials, never hardcode
- Keep the framework and all dependencies updated
- Review generated firewall rules before applying to production

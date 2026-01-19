# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**Please do not report security vulnerabilities publicly in GitHub issues.**

If you have discovered a potential security vulnerability in this project, please report it privately. We will work with you to verify the vulnerability and patch it.

### How to Report

1. **GitHub Security Advisories (Preferred)**: Use [GitHub's private vulnerability reporting](https://github.com/ctrl-alt-automate/netbox-ssl/security/advisories/new) to submit your report.

2. **Email**: If you cannot use GitHub Security Advisories, contact the maintainers directly through GitHub.

### What to Include

When reporting a vulnerability, please provide:

- Component(s) affected
- A description indicating how to reproduce the issue
- A summary of the security vulnerability and impact
- Any potential mitigations you have identified

### Response Timeline

- We will acknowledge receipt of your report within 48 hours
- We will provide an initial assessment within 7 days
- We will work with you to understand and resolve the issue

### Disclosure Policy

- We request that you give us reasonable time to resolve the vulnerability before public disclosure
- We will coordinate with you on the timing of any public announcements
- We will credit you in the security advisory (unless you prefer to remain anonymous)

## Security Considerations for This Plugin

This plugin handles TLS/SSL certificate data. Important security notes:

- **Private keys are never stored**: The plugin explicitly rejects any PEM content containing private keys
- **Certificate data is metadata only**: Only public certificate information is stored
- **Access control**: The plugin respects NetBox's permission system

## Policy

If we verify a reported security vulnerability, our policy is:

- We will patch the current release branch, as well as the immediate prior minor release branch
- After patching, we will immediately issue new security fix releases
- We will publish a security advisory detailing the vulnerability and fix

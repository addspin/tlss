# Security Policy

## Supported Versions

Upgrade to the latest version for all fixes.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via:

1. **GitHub Private Vulnerability Reporting:** [Report a vulnerability](https://github.com/addspin/tlss/security/advisories) (preferred)
2. **Email:** lab137@yandex.ru
3. **Telegram:** [@addspin](https://t.me/addspin) (private message)

### What to Include

- Type of vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Initial response:** within 48 hours
- **Status update:** within 7 days
- **Fix timeline:** depends on severity

### Severity Levels

| Severity | Description                         | Response            |
| -------- | ----------------------------------- | ------------------- |
| Critical | Remote code execution, auth bypass  | Immediate fix       |
| High     | Data exposure, privilege escalation | Fix within 7 days   |
| Medium   | Limited impact vulnerabilities      | Fix in next release |
| Low      | Minor issues                        | Scheduled fix       |

## Security Best Practices

When deploying TLSS:

1. **Authentication** - Do not use the configuration file to decrypt the encryption key. Use -  `authConfig: false`
2. **Use HTTPS** - Issue a server certificate using the service and include it in the configuration or use reverse proxies.
3. **Limit network access** - Use firewall rules
4. **Regular updates** - Keep TLSS updated to latest version
5. **Secure credentials** - Use complex passwords and salt to encrypt the key.

## Acknowledgments

I value any contribution to security and will credit security researchers who report real vulnerabilities in the release notes and changelog unless the reporter requests anonymity.
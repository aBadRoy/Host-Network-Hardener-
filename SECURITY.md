# Security Policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Report them privately
to the repository owner via GitHub's
[private vulnerability reporting](https://github.com/aBadRoy/Host-Network-Hardener-/security/advisories/new)
or by contacting the maintainer directly.

When reporting, include:

- The affected version and Python version
- A description of the vulnerability and its impact
- A minimal reproducer (command + target) if one exists

You can expect an acknowledgement within 5 business days and a fix plan as soon
as the issue is confirmed. We are happy to credit researchers who report issues
first, unless they prefer to remain anonymous.

## Supported versions

Only the latest release on the `main` branch is actively patched. Bug fixes and
security patches are backported on request when practical.

## Scope of this tool

This project performs **active network scanning** and **remote banner grabbing**.
It is intended for defensive security work against systems you own or are
authorized to test.

- Do not point it at systems without authorization.
- Remote content (banners, TLS certificates, server headers) is attacker-controlled
  input. It is sanitized before printing or writing to reports, but treat it as
  untrusted data.
- Reports may contain IP addresses, hostnames, software versions and other
  infrastructure details. Store and share them accordingly.

## Handling secrets

- Never commit credentials, API tokens or private scan data.
- `.gitignore` excludes local report output (`reports_*`) and logs.

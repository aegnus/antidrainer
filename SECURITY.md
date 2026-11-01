# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**. Do not open a public issue for security problems.

Include what you found, how to reproduce it, and what an attacker could do with it. You should get a first reply within a week.

## In scope

- A tested site escaping the sandbox: reading or controlling the bench page, reading the helper's key, or using the helper to reach your local network or the helper itself.
- The helper being reachable from other machines, or leaking cookies or credentials.
- A real wallet extension being exposed to the tested site through the bench.

## Out of scope

- Drainer kits that avoid detection. Please open a regular issue with a sample or fixture instead, so the rules can be improved.
- Behaviour of the sites you test.

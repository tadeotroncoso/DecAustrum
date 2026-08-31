# Security policy

## Project scope

DecAustrum is published as a source-available portfolio evaluation project. It
is not a hosted service, and this repository does not represent a public
production environment.

Security reports should concern the current default branch. Earlier commits,
forks, modified copies, and third-party deployments are outside the project's
security-reporting scope. No release currently carries a guaranteed support or
security-maintenance period.

## Reporting a vulnerability

Use GitHub's **Report a vulnerability** option in the repository's Security tab.
The repository is intended to be published with private vulnerability reporting
enabled so that technical details are not disclosed in a public issue.

If private reporting is unavailable, do not publish exploit details, secrets,
or proof-of-concept material in an issue or discussion. Contact the repository
owner through the GitHub profile without sensitive details and ask for a private
reporting channel. No alternative public reporting channel is provided.

A useful report includes:

- the affected commit and component;
- the security impact and conditions required to reproduce it;
- minimal reproduction steps using placeholder data;
- any relevant logs with credentials and personal data removed; and
- a suggested mitigation, when one is known.

## Handling and disclosure

Receiving a report does not create a support relationship, remediation promise,
response deadline, disclosure timetable, or bounty obligation. Reports may be
acknowledged, investigated, fixed, or declined at the owner's discretion. See
the [support policy](../SUPPORT.md) for the complete support position.

Do not publicly disclose a suspected vulnerability while a private review is in
progress. Any coordinated disclosure terms must be agreed separately.

## Safe evaluation

Security testing must be limited to a local copy that you control and must use
synthetic data and non-production credentials. Do not:

- test a third-party system or deployment without its owner's permission;
- attempt denial of service, social engineering, or credential theft;
- access, retain, or disclose data that does not belong to you; or
- use a report as authorization for production or commercial use.

The [license](../LICENSE) governs all use of the source code. This policy does
not expand the rights granted by that license.

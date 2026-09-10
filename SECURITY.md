Security Policy

⚡ Electric Money

Electric Money is an experimental blockchain project.

Security is a major area of ongoing development, and the current implementation has not undergone an independent professional security audit.

Please assume that vulnerabilities may exist.

Reporting a vulnerability

If you discover a security vulnerability, please avoid immediately publishing detailed exploitation instructions in a public GitHub issue.

Instead, report the issue privately to the project maintainers.

When reporting a vulnerability, please provide as much of the following information as possible:

- Description of the vulnerability
- Affected component
- Steps to reproduce
- Potential impact
- Whether the issue affects consensus
- Whether the issue can cause a chain split
- Whether funds or balances could be affected
- Proof of concept, if available
- Suggested mitigation, if you have one

Please do not include private keys, passwords or other sensitive information in a report.

Particularly important vulnerabilities

The following issues should be treated as high priority:

Consensus vulnerabilities

Examples include:

- accepting invalid blocks
- incorrect Proof-of-Work validation
- incorrect supply calculation
- bypassing the maximum supply
- invalid transaction acceptance
- nonce validation failures
- signature verification failures
- consensus divergence between nodes

Economic vulnerabilities

Examples include:

- creating EM without valid issuance
- bypassing taxes
- manipulating Treasury distributions
- obtaining disproportionate mining rewards
- exploiting accounting or rounding behavior

Networking vulnerabilities

Examples include:

- remote code execution
- denial of service
- uncontrolled memory consumption
- uncontrolled CPU consumption
- peer exhaustion
- malicious chain synchronization
- malformed network messages

Cryptographic vulnerabilities

Examples include:

- signature bypass
- transaction malleability
- weak randomness
- address forgery
- cryptographic implementation errors

Responsible disclosure

Please give maintainers a reasonable opportunity to investigate and fix a vulnerability before publicly disclosing detailed exploitation information.

Once a vulnerability has been investigated and addressed, public disclosure can be discussed with the reporter.

No security guarantees

Electric Money is experimental software.

There are currently no guarantees that:

- the blockchain is secure
- funds are safe
- consensus is bug-free
- the network can resist attacks
- the monetary policy is economically sound
- the software is suitable for production use

Do not use Electric Money with real funds.

Thank you for helping make the project safer. ⚡

# Security Policy

## Overview

This repository automates the execution of Atomic Red Team tests on macOS using GitHub Actions. Given the sensitive nature of security testing, this document outlines our security posture, threat model, and incident response procedures.

## Threat Model

### Assets
- **Execution Environment**: macOS runners with system-level access
- **Test Artifacts**: Execution logs containing system call traces and process information
- **Credentials**: GitHub tokens, runner registration tokens, potential test credentials
- **Source Code**: Workflow definitions and test configurations

### Threats
1. **Supply Chain Attacks**: Compromise of upstream dependencies (Atomic Red Team, PowerShell modules)
2. **Code Injection**: Malicious test definitions executed with elevated privileges
3. **Information Disclosure**: Sensitive data leaked through execution logs
4. **Privilege Escalation**: Abuse of sudo access in workflows
5. **Denial of Service**: Resource exhaustion through malicious tests
6. **Artifact Tampering**: Modification of execution logs post-collection

### Trust Boundaries
- **Trusted**: Repository maintainers, signed commits, pinned dependencies
- **Untrusted**: External PRs, unverified inputs, runtime-fetched content

## Security Controls

### 1. Supply Chain Security
- ✅ All GitHub Actions pinned to SHA commits
- ✅ Atomic Red Team installation script verified with SHA-256 checksum
- ✅ Git repositories cloned at specific commit hashes
- ✅ PowerShell modules validated before import
- ✅ Dependency review workflow enabled

### 2. Input Validation
- ✅ TTP identifiers validated against MITRE ATT&CK format
- ✅ Path traversal protection in file operations
- ✅ Command injection prevention via allowlisting
- ✅ Matrix strategy values validated

### 3. Access Control
- ✅ Workflow permissions restricted to minimum required
- ✅ CODEOWNERS enforced for critical paths
- ✅ Branch protection rules on main branches
- ✅ Required reviews for workflow changes
- ✅ Self-hosted runner access controls

### 4. Runtime Security
- ✅ Timeout limits on test execution (60 seconds per test, 30 minutes per job)
- ✅ Concurrency limits to prevent resource exhaustion
- ✅ Elevated privileges justified and audited
- ✅ Network egress monitoring via eslogger
- ✅ Process isolation per test execution

### 5. Data Protection
- ✅ Sensitive data filtered from execution logs
- ✅ Artifact retention limited to 30 days
- ✅ Secret scanning enabled
- ✅ No credentials stored in repository
- ✅ Logs sanitized before upload

### 6. Monitoring & Detection
- ✅ Workflow execution monitored for anomalies
- ✅ Failed authentication attempts logged
- ✅ Unexpected privilege escalations alerted
- ✅ Dependency updates tracked
- ✅ Execution logs analyzed for IOCs

## Security Best Practices

### For Contributors
1. **Never commit secrets** - Use GitHub Secrets for sensitive data
2. **Validate all inputs** - Assume all external input is malicious
3. **Pin dependencies** - Always use commit SHAs for actions and specific versions for tools
4. **Minimize privileges** - Request only the permissions you need
5. **Review test definitions** - Audit Atomic Red Team tests before execution
6. **Sanitize outputs** - Remove sensitive data from logs and artifacts

### For Reviewers
1. **Verify checksums** - Ensure all downloaded content is validated
2. **Check for injection** - Look for unescaped variables in shell commands
3. **Review permissions** - Ensure workflow permissions are minimal
4. **Audit sudo usage** - Justify all elevated privilege operations
5. **Test in isolation** - Run untrusted tests in sandboxed environments

### For Operators
1. **Rotate runner tokens** - Refresh self-hosted runner credentials regularly
2. **Monitor execution** - Watch for anomalous test behavior
3. **Update dependencies** - Keep Atomic Red Team and modules current
4. **Review artifacts** - Audit execution logs for security events
5. **Incident response** - Have a plan for compromised runners

## Vulnerability Disclosure

### Reporting a Vulnerability
If you discover a security vulnerability, please report it via:
- **Email**: security@[your-domain].com (preferred)
- **GitHub Security Advisory**: Use "Security" tab in repository

**Do NOT** create public issues for security vulnerabilities.

### Response Timeline
- **24 hours**: Initial acknowledgment
- **7 days**: Preliminary assessment and severity classification
- **30 days**: Fix development and testing
- **60 days**: Public disclosure (coordinated)

### Severity Classification
We use CVSS 3.1 for severity scoring:
- **Critical (9.0-10.0)**: Immediate action, emergency patch
- **High (7.0-8.9)**: Priority fix, next release
- **Medium (4.0-6.9)**: Standard fix, planned release
- **Low (0.1-3.9)**: Best-effort, future release

## Known Security Considerations

### Atomic Red Team Tests
- Tests are designed to simulate adversary behavior
- Some tests may trigger security tools and alerts
- Tests may create files, registry keys, or network connections
- Cleanup procedures are defined but may not be perfect
- Always run in controlled, non-production environments

### Self-Hosted Runners
- Runners have access to network and filesystem
- Compromise of a runner could lead to lateral movement
- Runners should be ephemeral and rebuilt regularly
- Network segmentation recommended
- Monitor runner activity continuously

### Execution Logs
- May contain command-line arguments with sensitive data
- May include environment variables
- May expose internal network topology
- May reveal security tool configurations
- Sanitization applied but review before external sharing

## Compliance

This tool is designed for authorized security testing only:
- ✅ Red team exercises
- ✅ Purple team collaboration
- ✅ Detection engineering validation
- ✅ Security control testing
- ✅ Threat hunting research

**Unauthorized use for malicious purposes is strictly prohibited.**

## Security Checklist

Before running tests:
- [ ] Tests reviewed and understood
- [ ] Environment isolated from production
- [ ] Monitoring and logging enabled
- [ ] Cleanup procedures verified
- [ ] Stakeholders notified
- [ ] Rollback plan prepared
- [ ] Incident response team on standby

After running tests:
- [ ] Logs reviewed for anomalies
- [ ] Cleanup verified
- [ ] Artifacts securely stored
- [ ] Results documented
- [ ] Lessons learned captured
- [ ] Environment reset or destroyed

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Atomic Red Team Documentation](https://github.com/redcanaryco/atomic-red-team)
- [GitHub Actions Security Hardening](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)

## Version History

- **v2.0** (2025-11-15): Comprehensive security hardening implementation
- **v1.0** (Initial): Basic workflow with minimal security controls

---

**Last Updated**: 2025-11-15
**Security Team Contact**: See vulnerability disclosure section above

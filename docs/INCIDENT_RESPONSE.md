# Incident Response Playbook

## Purpose
This playbook provides step-by-step procedures for responding to security incidents involving the Atomic Red Team testing framework.

## Incident Classification

### Severity Levels

| Level | Definition | Response Time | Example |
|-------|------------|---------------|---------|
| **P0 - Critical** | Active compromise, data breach | Immediate (< 15 min) | Malicious code in workflow, runner compromise |
| **P1 - High** | Potential compromise, active attack | < 1 hour | Suspicious test execution, unauthorized changes |
| **P2 - Medium** | Security control failure | < 4 hours | Failed validation, logging issues |
| **P3 - Low** | Minor security event | < 24 hours | Policy violation, configuration drift |

---

## P0: Critical Incident Response

### Scenario 1: Compromised GitHub Actions Workflow

**Indicators**:
- Unauthorized workflow modifications
- Execution of unexpected commands
- Unusual network connections
- Privilege escalation attempts

**Response Steps**:

#### 1. Immediate Containment (0-15 minutes)

```bash
# Disable the workflow immediately
# Via GitHub UI: Settings → Actions → Disable workflow

# Or via GitHub CLI
gh workflow disable "Atomic Red Team Demo"

# Revoke runner tokens
# GitHub Settings → Actions → Runners → Remove runner
```

#### 2. Investigation (15-60 minutes)

```bash
# Check workflow run logs
gh run list --workflow="Atomic Red Team Demo" --limit 20

# Download suspicious run logs
gh run view <run-id> --log

# Check for unauthorized commits
git log --all --oneline --graph --decorate -20

# Check for force pushes
git reflog

# Review artifact uploads
gh run list --workflow="Atomic Red Team Demo" | grep "completed"
gh run download <run-id>

# Examine runner activity
# Check runner logs on self-hosted machine
sudo journalctl -u actions.runner.* -n 1000
```

#### 3. Evidence Collection

```bash
# Create incident directory
INCIDENT_ID="INC-$(date +%Y%m%d-%H%M%S)"
mkdir -p ~/incidents/$INCIDENT_ID

# Collect workflow history
gh run list --workflow="Atomic Red Team Demo" --limit 100 --json databaseId,status,conclusion,createdAt > ~/incidents/$INCIDENT_ID/workflow_history.json

# Collect repository state
git bundle create ~/incidents/$INCIDENT_ID/repo_snapshot.bundle --all

# Collect artifacts
gh run list --status completed | while read run_id _; do
  gh run download $run_id -D ~/incidents/$INCIDENT_ID/artifacts/$run_id
done

# System state (if runner accessible)
ps auxf > ~/incidents/$INCIDENT_ID/processes.txt
netstat -tlnp > ~/incidents/$INCIDENT_ID/network.txt
sudo find /tmp -type f -mtime -1 > ~/incidents/$INCIDENT_ID/temp_files.txt
```

#### 4. Remediation

```bash
# Revert malicious changes
git revert <malicious_commit_sha>

# Or force reset (extreme cases only)
git reset --hard <known_good_commit>
git push --force origin main

# Rotate all secrets
# GitHub Settings → Secrets → Rotate all

# Rebuild runner
# Decommission compromised runner
# Provision new runner with clean image

# Review and update security controls
# Apply lessons learned
```

#### 5. Recovery

```bash
# Verify clean state
./scripts/validate-ttp.sh T1569.001-1
./scripts/security-scan.sh

# Re-enable workflow
gh workflow enable "Atomic Red Team (Security Hardened)"

# Monitor closely
gh run watch
```

#### 6. Post-Incident (1-7 days)

- [ ] Root cause analysis completed
- [ ] Lessons learned documented
- [ ] Security controls updated
- [ ] Team debriefing conducted
- [ ] Stakeholders notified
- [ ] Public disclosure (if required)

---

### Scenario 2: Runner Compromise

**Indicators**:
- Unusual CPU/memory usage
- Unexpected network connections
- Unauthorized files created
- Suspicious process execution

**Response Steps**:

#### 1. Immediate Containment

```bash
# Isolate runner from network (if accessible)
sudo iptables -A OUTPUT -j DROP
sudo iptables -A INPUT -j DROP
# Allow SSH for investigation
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
sudo iptables -A OUTPUT -p tcp --sport 22 -j ACCEPT

# Stop runner service
sudo systemctl stop actions.runner.*

# Kill suspicious processes
sudo pkill -9 eslogger  # if running unexpectedly
ps auxf | grep -i atomic
# Kill any suspicious processes
```

#### 2. Forensic Collection

```bash
# Memory dump (if available)
sudo dd if=/dev/mem of=/tmp/memory.dump bs=1M

# Disk image
sudo dd if=/dev/sda of=/tmp/disk.img bs=4M status=progress

# Live response data
sudo netstat -anp > /tmp/network_connections.txt
sudo lsof > /tmp/open_files.txt
sudo ps auxef > /tmp/processes.txt

# Copy to secure location
scp /tmp/{memory.dump,disk.img,*.txt} forensics@secure-server:/cases/$INCIDENT_ID/
```

#### 3. Containment & Eradication

```bash
# Destroy compromised runner
# Remove runner registration
gh api repos/:owner/:repo/actions/runners/<runner-id> -X DELETE

# Terminate instance (cloud)
# AWS
aws ec2 terminate-instances --instance-ids i-xxxxx

# Or physical
# Wipe and reimage
sudo dd if=/dev/zero of=/dev/sda bs=1M
# Reinstall OS
```

#### 4. Recovery

```bash
# Provision new runner
# Use Infrastructure as Code
terraform apply -target=module.github_runner

# Verify security configuration
./scripts/runner-security-check.sh

# Register with GitHub
./config.sh --url https://github.com/org/repo --token <token>
```

---

### Scenario 3: Secrets Exposure

**Indicators**:
- Secrets found in logs
- Secrets in artifacts
- Secrets in public commits
- Third-party alert about leaked credentials

**Response Steps**:

#### 1. Immediate Revocation

```bash
# Identify exposed secrets
grep -r "password\|secret\|token\|api.key" artifacts/

# Revoke immediately
# GitHub PAT
gh api -X DELETE /applications/:client_id/token -f access_token=<token>

# AWS Keys
aws iam delete-access-key --access-key-id AKIA...

# Other services
# Follow service-specific revocation procedures
```

#### 2. Damage Assessment

```bash
# Check secret usage logs
# AWS CloudTrail
aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=<user>

# GitHub audit log
gh api /orgs/:org/audit-log

# Identify unauthorized access
# Check for unusual API calls, data access, resource creation
```

#### 3. Containment

```bash
# Rotate all related secrets
# Generate new secrets
openssl rand -hex 32 > new_secret.txt

# Update GitHub Secrets
gh secret set API_KEY < new_secret.txt

# Update downstream services
# Update all services that use the exposed secret
```

#### 4. Remediation

```bash
# Remove secrets from history (if committed)
# Use BFG Repo Cleaner
bfg --replace-text secrets.txt repo.git
cd repo.git
git reflog expire --expire=now --all
git gc --prune=now --aggressive

# Force push
git push --force --all origin

# Notify collaborators to re-clone
```

#### 5. Prevention

```bash
# Enable secret scanning
# GitHub Settings → Security → Secret scanning

# Add pre-commit hooks
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
gitleaks protect --staged --verbose
EOF
chmod +x .git/hooks/pre-commit

# Update .gitleaks.toml with new patterns
```

---

## P1: High Priority Incidents

### Scenario 4: Malicious Test Execution

**Indicators**:
- Unexpected test behavior
- Tests writing to unusual locations
- Network connections to suspicious IPs
- Persistence mechanisms created

**Response Steps**:

1. **Stop test execution**
   ```bash
   # Cancel running workflows
   gh run cancel <run-id>

   # Stop eslogger
   sudo pkill eslogger
   ```

2. **Collect evidence**
   ```bash
   # Download execution logs
   gh run download <run-id>

   # Analyze eslogger output
   cat eslogger.json | jq '.[] | select(.event=="exec")'
   ```

3. **Analyze test definition**
   ```bash
   # Review test YAML
   cat atomic-red-team/atomics/T*/T*.yaml

   # Check for suspicious commands
   grep -i "curl\|wget\|nc\|ncat" atomic-red-team/atomics/T*/T*.yaml
   ```

4. **Clean up artifacts**
   ```bash
   # Run cleanup
   pwsh -Command "Invoke-AtomicTest T1234 -Cleanup"

   # Manual cleanup if needed
   find / -name "*malicious*" -delete
   ```

---

## Communication Templates

### Internal Notification (P0)

```
SECURITY INCIDENT - P0 CRITICAL

Incident ID: INC-20250115-143022
Time Detected: 2025-01-15 14:30:22 UTC
Status: INVESTIGATING

Affected System: Atomic Red Team GitHub Actions
Potential Impact: Workflow compromise, code execution
Current Status: Workflow disabled, investigation ongoing

Actions Taken:
- Workflow disabled
- Runner isolated
- Evidence collection in progress

Next Update: In 30 minutes (15:00 UTC)

Contact: security-team@company.com
```

### External Disclosure (if required)

```
Security Advisory: Atomic Red Team Workflow Incident

Date: 2025-01-15
Severity: High
Status: Resolved

Summary:
On January 15, 2025, we identified unauthorized modifications to our
Atomic Red Team testing workflow. The issue was contained within 15
minutes, and we have no evidence of data exposure.

Timeline:
- 14:30 UTC: Incident detected
- 14:35 UTC: Workflow disabled
- 14:45 UTC: Runner isolated
- 16:00 UTC: Root cause identified
- 18:00 UTC: Remediation complete
- 20:00 UTC: Service restored

Impact:
- No user data exposed
- No production systems affected
- Limited to test environment

Actions Taken:
- Workflow reverted to known-good state
- All secrets rotated
- Enhanced monitoring deployed
- Security controls hardened

Recommendations:
- Users should re-clone repository
- Review any tests executed during incident window
- Report any suspicious activity

Contact: security@company.com
```

---

## Escalation Matrix

| Severity | Notify | Timeframe |
|----------|--------|-----------|
| P0 | Security Lead, CTO, CEO | Immediate |
| P0 | Security Team | Immediate |
| P0 | Legal Team | 1 hour |
| P0 | PR Team | 2 hours (if public-facing) |
| P1 | Security Lead | 30 minutes |
| P1 | Security Team | 1 hour |
| P2 | Security Team | 4 hours |
| P3 | Security Team | 24 hours |

---

## Recovery Validation Checklist

Before declaring incident resolved:

- [ ] Malicious code removed and verified
- [ ] All secrets rotated
- [ ] Security controls validated
- [ ] Monitoring enhanced
- [ ] Root cause documented
- [ ] Preventive measures implemented
- [ ] Team debriefing completed
- [ ] Stakeholders notified
- [ ] Post-mortem scheduled
- [ ] Lessons learned documented

---

## Post-Incident Review Template

```markdown
# Incident Post-Mortem

**Incident ID**: INC-YYYYMMDD-HHMMSS
**Date**: YYYY-MM-DD
**Severity**: P0/P1/P2/P3
**Duration**: X hours Y minutes

## Summary
Brief description of what happened

## Timeline
- HH:MM - Event occurred
- HH:MM - Detected
- HH:MM - Contained
- HH:MM - Resolved

## Root Cause
Detailed technical analysis

## Impact
- Systems affected
- Data exposure
- Downtime

## Response Effectiveness
What went well / What could be improved

## Action Items
1. [ ] Immediate fix (Owner: X, Due: Date)
2. [ ] Long-term improvement (Owner: Y, Due: Date)

## Lessons Learned
Key takeaways for the team
```

---

## Contact Information

| Role | Contact | Phone |
|------|---------|-------|
| Security Lead | security-lead@company.com | +1-XXX-XXX-XXXX |
| On-Call Engineer | oncall@company.com | +1-XXX-XXX-XXXX |
| Legal | legal@company.com | +1-XXX-XXX-XXXX |
| PR Team | pr@company.com | +1-XXX-XXX-XXXX |

## External Resources

- [GitHub Security](https://docs.github.com/en/code-security)
- [NIST Incident Response Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
- [SANS Incident Handler's Handbook](https://www.sans.org/white-papers/33901/)

---

**Last Updated**: 2025-11-15
**Next Review**: 2026-02-15
**Owner**: Security Engineering Team

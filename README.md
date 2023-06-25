# What does this do?
Run atomic red team tests for macOS inside a Github Runner using Github actions.

Targeted to Atomic test contributors and detection engineers.

Inputs:
- Atomic red team folder. Inside the repo for now.
- List of Techniques and tests

Outputs:
- Execution log
- eslogger/ESF output

# Future Roadmap
- [ ] Self-hosted runners 
- [ ] Input from external atomics github repo
- [x] Keep artifacts
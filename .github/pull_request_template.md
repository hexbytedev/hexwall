---
name: Pull request
about: Submit a pull request for pihole-guard
title: ''
labels: ''
assignees: ''

---

## Description

Summarize the change, the motivation, and any relevant implementation context.

## Type of change

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Refactor or internal cleanup
- [ ] Documentation update
- [ ] Breaking change

## How has this been tested?

List the commands you ran and any manual verification steps.

```text
go test ./...
golangci-lint run ./...
revive ./...
```

If you skipped any checks, explain why.

- [ ] `go test ./...`
- [ ] `golangci-lint run ./...`
- [ ] `revive ./...`
- [ ] Manual runtime verification

**Test Configuration**:

- OS name and version:
- Go compiler version:
- `somo` version:
- Pi-hole DB source:
- Mode used (`watch` or `enforce`):

## Checklist

- [ ] My code follows the style guidelines of this project
- [ ] I have performed a self-review of my own code
- [ ] I have made corresponding changes to the documentation
- [ ] My changes generate no new lint or vet issues
- [ ] I have updated or intentionally skipped tests with explanation above

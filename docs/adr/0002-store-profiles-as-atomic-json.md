# Store Profiles as atomic user-global JSON files

ACS stores each Profile at `~/.acs/profiles/<name>.json`. The profiles directory is user-only (`0700`), and each Profile is a user-only file (`0600`). A Profile is first written and synced as a temporary file in that directory, then atomically published without replacing an existing name.

Profile names contain 1–64 ASCII letters, numbers, dots, underscores, or hyphens and start with a letter or number. Creating an existing name fails; editing and overwriting remain outside the MVP.

The human-readable schema is versioned:

```json
{
  "version": 1,
  "name": "backend-review",
  "target": "devin",
  "skillReferences": [
    {
      "source": "devin-config",
      "relativePath": "code-review"
    },
    {
      "source": "shared-agents",
      "relativePath": "postgres-review"
    }
  ]
}
```

Each Skill Reference stores the Devin Adapter's explicit global source identity and the Skill Bundle-relative path. Display names and absolute paths are deliberately not identities, so a later launch can fail when a bundle moves instead of silently rebinding the Profile.

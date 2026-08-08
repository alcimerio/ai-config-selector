# ORCA and PASEO release workflow comparison

Research date: 2026-08-08.

Repositories inspected:

- [stablyai/orca](https://github.com/stablyai/orca)
- [getpaseo/paseo](https://github.com/getpaseo/paseo)

Only public repository state is covered. Private environment settings, secrets,
and organization policies cannot be inferred when they are not exposed by a
workflow or a public GitHub API response.

## ORCA

ORCA has a single `Cut Release` workflow whose primary entry point is a manual
`workflow_dispatch`. The workflow receives the release kind and source ref,
runs with `contents: write`, creates a release commit, creates an annotated tag,
and pushes both from GitHub Actions. It then creates a draft GitHub Release,
builds the artifacts, verifies that the draft and required assets are complete,
and changes the draft to published.

Sources:

- [release-cut workflow: entry point and declared flow](https://github.com/stablyai/orca/blob/main/.github/workflows/release-cut.yml#L1-L64)
- [release-cut workflow: release commit, annotated tag, and push](https://github.com/stablyai/orca/blob/main/.github/workflows/release-cut.yml#L660-L765)
- [release-cut workflow: final draft verification and publication](https://github.com/stablyai/orca/blob/main/.github/workflows/release-cut.yml#L1729-L1794)
- [public Releases](https://github.com/stablyai/orca/releases)

The workflow configures the commit and tag author as
`github-actions[bot]`. Public release metadata likewise reports
`github-actions[bot]` as the publisher. Recent `Cut Release` workflow runs were
manually dispatched by several human maintainers, so ORCA is not an example of
a single maintainer using a bot as an independent approver.

No `environment:` is declared in `release-cut.yml` or the separate macOS build
workflow. The repository's public rulesets endpoint returned no active public
rulesets during this inspection. Consequently, the public implementation does
not show a protected-environment approval between automation and publication.

## PASEO

PASEO uses a maintainer-driven release command. Its root package scripts run
release checks, update versions, publish the npm packages, and finally invoke
`scripts/push-current-release-tag.mjs`. That script creates an annotated
`v<version>` tag locally when needed, pushes the current branch, and then pushes
the tag.

Sources:

- [root release scripts](https://github.com/getpaseo/paseo/blob/main/package.json)
- [tag push script](https://github.com/getpaseo/paseo/blob/main/scripts/push-current-release-tag.mjs)

The pushed tag triggers `Desktop Release`. GitHub Actions uses the repository
`GITHUB_TOKEN` with `contents: write` to create the GitHub Release and upload
the macOS, Linux, and Windows artifacts. A manual dispatch exists for rebuilding
an existing tag, but it does not create the canonical tag.

Sources:

- [desktop release triggers and release creation](https://github.com/getpaseo/paseo/blob/main/.github/workflows/desktop-release.yml#L1-L100)
- [release-note synchronization](https://github.com/getpaseo/paseo/blob/main/.github/workflows/release-notes-sync.yml)
- [public Releases](https://github.com/getpaseo/paseo/releases)

The recent tags and workflow runs sampled on 2026-08-08 were created/pushed by
the maintainer account `boudra`; the resulting GitHub Releases report
`github-actions[bot]` as publisher. For example, the annotated `v0.2.3` tag
records Mohamed Boudra as tagger, while the tag-triggered desktop workflow and
Release use GitHub Actions for artifact publication.

Neither `desktop-release.yml` nor `release-notes-sync.yml` declares an
`environment:`. The public rulesets API exposed one active ruleset for the
default branch with required CI checks and no public tag ruleset. Thus the
public release path does not show a bot-initiated deployment followed by a
protected-environment approval.

## Comparison and implication

| Repository | Canonical tag | GitHub Release publisher | Human environment approval |
| --- | --- | --- | --- |
| ORCA | Created inside a manually dispatched Actions workflow as `github-actions[bot]` | `github-actions[bot]` | Not present in the public workflow |
| PASEO | Created and pushed from the maintainer's local release command | `github-actions[bot]` after tag push | Not present in the public workflow |

Both projects rely on deterministic automation and CI rather than a second
approval principal at publication time. ORCA automates the release cut itself;
PASEO keeps the canonical tag decision on the maintainer's machine. Neither is
an implementation of “a bot initiates the deployment and the sole maintainer
approves a protected environment.”

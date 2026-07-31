# AI Config Selector

The domain of named, reusable capability selections for AI coding CLIs. Profiles express a user's intended global skill set without changing the user's real global installation.

## Language

**Profile**:
A named, user-global, machine-local saved selection for one target CLI, comprising zero or more selected Skill References. A Profile is available from any working directory, and its name is unique within the user's ACS profiles.
_Avoid_: configuration, preset, project profile

**Skill Reference**:
A profile entry that identifies one selected global Skill Bundle by its source location and bundle-relative path; it is resolved against the current Skill Catalog at launch. It never silently rebinds to a different bundle.
_Avoid_: skill name, skill copy

**Skill Bundle**:
The complete directory of a selectable skill, including its `SKILL.md` and any relative scripts, references, or assets.
_Avoid_: skill file, SKILL.md

**Skill Catalog**:
The current discovered set of global Skill Bundles, including each bundle's source location and identity. The catalog may contain duplicate display names from different sources.
_Avoid_: skill list, source directory

**Default Profile**:
A future selection rule that chooses a Profile when a launch omits an explicit profile name. It may be defined at the user or project level without changing what a Profile is.
_Avoid_: implicit profile, active profile

**Session**:
One ephemeral ACS-managed launch environment at `~/.acs/sessions/<run-id>`, containing the selected Skill Bundles and lasting only for its child CLI process.
_Avoid_: workspace, profile

**CLI Adapter**:
The CLI-specific boundary that discovers global Skill Bundles, prepares a Session, verifies the installed CLI's capabilities, and starts the child process.
_Avoid_: core, launcher

**Adapter Preflight**:
A focused runtime verification that an installed CLI sees exactly the Session's selected global Skill Bundles and retains the required usable login.
_Avoid_: version check, full integration test

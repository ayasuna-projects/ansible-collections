# Contributing

This file defines the contribution guidelines of the project.

## Documentation

This section defines the documentation style and process of the project.

### Purpose and audience

- The documentation of the project is generally written and managed by an AI agent. It is intended for both human and AI agent consumption.
- Human readability takes precedence over AI agent readability.
- The documentation describes the API and specification of the project. It does not describe implementation details (those are held in `AGENTS.md`).

### Structure of `CONTRIBUTING.md`

- The `CONTRIBUTING.md` file documents the contribution guidelines of the project.
- The primary heading of the file is `# Contributing`, derived from its file name.
- A short summary of what can be found in the file follows directly under the primary heading.
- The remainder of the file consists of one or more second-level sections.
- One of the second-level sections is the `## Documentation` section that this section is a part of.

### Updating the documentation

- After any change to the project, whether made by a human or by an AI agent, the project documentation must be updated to encompass the change.
- If an AI agent introduces the change, the agent must update the documentation as part of the implementation process, even if it was not explicitly asked to.
- Updating the documentation means updating the relevant Markdown and asset files. This includes `docs/INDEX.md` and, if necessary, `AGENTS.md`, `CONTRIBUTING.md` and `README.md`.

### File placement

- All documentation files (Markdown and assets), apart from the root `AGENTS.md`, `CONTRIBUTING.md` and `README.md`, must be placed within `docs/`.
- Files and directories within `docs/` may be created as necessary and at any depth.

### Naming

- All file names within `docs/` must follow the format `UPPER_SNAKE_CASE.ext` with a lowercase file extension (for example `QUICKSTART.md` or `IMAGE.jpg`).
- All directory names within `docs/` must be in `lower_snake_case`.
- File names may only contain alphanumeric characters, `_` and a single `.` separating the name from the extension.
- Directory names may only contain alphanumeric characters and `_`.
- The only exception is the `docs/.assets/` directory. It starts with a `.`.
- The primary heading of a Markdown file is derived from its file name. `SETUP_GUIDELINES.md` becomes `# Setup Guidelines`.
- Examples of valid paths: `docs/QUICKSTART.md`, `docs/path_segment/FILE_NAME.md`, `docs/.assets/IMAGE.jpg`.
- Examples of invalid paths: `docs/quickstart.md`, `docs/Path_Segment/FILE_NAME.md`, `docs/my-dir/FILE_NAME.md`, `docs/assets/IMAGE.jpg`.

### Asset files

- All documentation related non-Markdown files (images, PDFs, ...) must be placed in the `docs/.assets/` directory or a subdirectory of it.
- Assets are referenced from Markdown files via links, for example `[Report](.assets/REPORT.pdf)` or for images `![Architecture diagram](.assets/ARCHITECTURE_DIAGRAM.png)`.

### Index file

- The `docs/INDEX.md` file provides the index for the documentation files within `docs/`.
- The primary heading of the file is `# Index`, derived from its file name.
- It has two second-level sections (`## Documents` and `## Assets` in that order), each containing a list of `index entries`.
- There is a single `index entry` for each file within `docs/` (including assets), except for the `docs/INDEX.md` file itself.
- Each `index entry` consists of:
  - A link to the file it is for
    - For documents (Markdown files) `<link name>` in `[<link name>](<path to file>)` is equal to `<path to file>`
    - For assets the `<link name>` in `[<link name>](<path to file>)` is equal to `<path to file>` minus the `.asset/` prefix
  - A short summary, at most two sentences long, of the contents of the linked file
  - 1 to 5 keywords that are related to the contents of the file
    - The keywords are always written in lowercase
- Within each second-level section, `index entries` are sorted by the file path they link to, using case-sensitive ASCII order.

The structure of the index file is as follows.

```markdown
# Index

## Documents

### [QUICKSTART.md](QUICKSTART.md)

**Summary:** A minimal set of instructions to get started with the project

**Keywords:** setup

### [api_reference/ENDPOINTS.md](api_reference/ENDPOINTS.md)

**Summary:** A reference for the endpoints the project exposes

**Keywords:** api, endpoints, reference

## Assets

### [REPORT.pdf](.assets/REPORT.pdf)

**Summary:** Contains a report

**Keywords:** diagrams, report
```

### Linking

- When referencing other files of the documentation, links of the form `[<link name>](<path to file>)` must be used.
- Link paths must be relative to the file that contains the link.
- The `<link name>` in `[<link name>](<path to file>)` does not need to be the name of the referenced file if another term (or sequence of terms) makes more sense in the current context.

### Entry points: `README.md` and `AGENTS.md`

The project root directory holds two entry point files with distinct roles.

- `README.md` is the human entry point of the project. It stays short and provides a short overview over the project. It must contain a link to `CONTRIBUTING.md` and to `docs/INDEX.md`. It may either contain a quickstart section or point to `docs/QUICKSTART.md` (or a similar file) for a still brief but more exhaustive introduction into how to get started with the project (this normally includes simplified installation instructions for the project).
- `AGENTS.md` is the AI agent entry point of the project. It must point to `CONTRIBUTING.md`, `README.md` and `docs/INDEX.md`. It holds the implementation details and other information that is important for AI agents to know.

### Linting

- When an AI agent is asked to `lint` the documentation, it must check all documentation files (that is, the root `AGENTS.md`, `CONTRIBUTING.md` and `README.md` plus everything within `docs/`) for dead links, style, readability and up-to-date information.
- This may be a very expensive operation. The user may also specify that the agent is only to `lint` a specific part of the documentation.
- The `linting` process is responsible for cleaning up the documentation. This includes (partial) restructurings as necessary. Any restructuring must keep `docs/INDEX.md` in sync with the new file locations.
- If the `docs/INDEX.md` file is to be `linted`, the keywords associated with each `index entry` must also be normalized (lowercase, alphabetically sorted, without duplicates).
- If the `linting` process finds a directory within `docs/` that contains exactly one Markdown file and nothing else, it performs the following steps:
  1. Move the file to the parent directory and rename it to `<directory name>.md`, where `<directory name>` is the `UPPER_SNAKE_CASE` name of the directory the file currently resides in.
  2. Derive the new primary heading of the file from its new file name (see *Naming*).
  3. If a file with that name already exists in the parent directory, merge the moved file's content into it (the existing file's primary heading is kept and duplicated content is removed).
  4. Remove the now empty directory.
  5. Update the `index entries` in `docs/INDEX.md` to reflect the new file location and name.
  
### Example directory structure

The following example shows a valid `docs/` directory structure and the contents of its Markdown files. Directories are listed before files.

```text
docs/
├── .assets/
│   └── REPORT.pdf
├── api_reference/
│   └── ENDPOINTS.md
├── INDEX.md
└── QUICKSTART.md
```

`docs/INDEX.md`:

```markdown
# Index

## Documents

### [QUICKSTART.md](QUICKSTART.md)

**Summary:** A minimal set of instructions to get started with the project

**Keywords:** setup

### [api_reference/ENDPOINTS.md](api_reference/ENDPOINTS.md)

**Summary:** A reference for the endpoints the project exposes

**Keywords:** api, endpoints, reference

## Assets

### [REPORT.pdf](.assets/REPORT.pdf)

**Summary:** Contains a report

**Keywords:** diagrams, report
```

`docs/QUICKSTART.md`:

```markdown
# Quickstart

A minimal set of instructions to get started with the project.

1. Set up the development environment.
2. Build the project.
3. Verify the setup by running the project.
```

`docs/api_reference/ENDPOINTS.md`:

```markdown
# Endpoints

A reference for the endpoints the project exposes.

- `GET /status`: Returns the current status of the project.
- `POST /actions`: Triggers an action of the project.
```

## Code Style

This section defines the code style of the project.

### Variable naming

Every variable name consists of three components joined by a double underscore: `<declarer>__<type>__<name>`. For example, `ayasuna__ingot__k8s__inputs__name` is the input `name` of the role `ayasuna.ingot.k8s`.

- `<declarer>` — the thing that declares the variable:
  - For playbook variables, the name of the playbook (e.g. `build_ingot`).
  - For role variables, the role's FQN with each dot replaced by `__` (e.g. `ayasuna.ingot.k8s` becomes `ayasuna__ingot__k8s`).
  - For inventory variables, the name of the host group that declares them (e.g. `all`).
- `<type>` — what the variable is for:
  - `inputs` — input parameters of a playbook or role. These must always be declared in the corresponding argument spec.
  - `privates` — variables that are internal to the declaring playbook, role or host group. They must not be read or written from outside of it.
  - `outputs` — the result (i.e. return value) of a playbook or role. The declarer sets them itself; tasks running afterwards may consume them.
- `<name>` — the identifier of the variable within its declarer.
- Naming rules: variable names are lowercase and may only contain letters, digits and underscores. Within a component, only single underscores may occur, with one exception: inside the `<declarer>` component, each dot of a role FQN becomes a double underscore (e.g. `ayasuna__ingot__k8s`).

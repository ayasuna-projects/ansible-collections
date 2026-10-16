# Contributing

This file defines the contribution guidelines of the project.

## Documentation

This section defines the documentation style and process of the project.

### Purpose and audience

- The documentation of the project is generally written and managed by an AI agent. It is intended for both human and AI agent consumption.
- Human readability takes precedence over AI agent readability.
- The documentation covers the API and specification of the project. It may also include implementation details that are relevant for human readers, any information intended specifically for AI agents however should be placed in `AGENTS.md`.

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
    - For documents (Markdown files) `<link_name>` in `[<link_name>](<path_to_file>)` is equal to `<path_to_file>`
    - For assets the `<link_name>` in `[<link_name>](<path_to_file>)` is equal to `<path_to_file>` minus the `.assets/` prefix
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

- When referencing other files of the documentation, links of the form `[<link_name>](<path_to_file>)` must be used.
- Link paths must be relative to the file that contains the link.
- The `<link_name>` in `[<link_name>](<path_to_file>)` does not need to be the name of the referenced file if another term (or sequence of terms) makes more sense in the current context.

### Placeholder

Within the prose of the documentation, **placeholders** are written in backticks with the label enclosed in angle brackets, for example `<directory>` in `<directory>/config.json`.

### Entry points: `README.md` and `AGENTS.md`

The project root directory holds two entry point files with distinct roles.

- `README.md` is the human entry point of the project. It stays short and provides a short overview over the project. It must contain a link to `CONTRIBUTING.md` and to `docs/INDEX.md`. It may either contain a quickstart section or point to `docs/QUICKSTART.md` (or a similar file) for a still brief but more exhaustive introduction into how to get started with the project (this normally includes simplified installation instructions for the project).
- `AGENTS.md` is the AI agent entry point of the project. It must point to `CONTRIBUTING.md`, `README.md` and `docs/INDEX.md`. It holds the implementation details and other information that is important for AI agents to know.

### Module, role and ingot role documentation file structure

This section defines the structure of the documentation files for the modules, roles and ingot roles of the project. It also defines the list formats that are shared by their `Parameters`, `Return values` and `References` sections.

#### Module documentation

The documentation of a module is a single Markdown file within `docs/` (see [File placement](#file-placement) and [Naming](#naming)). Its content has the following structure:

- The primary heading is the name of the module, derived from the file name.
- A short introduction describing what the module does.
- A `## Usage` section describing how the module can be used, typically including a complete example.
- Any number (possibly zero) of module-specific second-level sections between `Usage` and `Parameters`, covering topics that do not fit into the fixed sections (for example, the concepts, the behavior, or specific features of the module).
- A `## Parameters` section consisting of a short introduction (for example, "The module has the following parameters") and a list of all parameters of the module in the format defined in [Parameters and return values](#parameters-and-return-values).
- A `## Return values` section consisting of a short introduction and a list of all return values of the module in the format defined in [Parameters and return values](#parameters-and-return-values).
- A `## References` section containing a list of links in the format defined in [References](#references).

The skeleton of the structure is as follows.

```markdown
# <module_name>

<short_description_of_the_module>

## Usage

<how_the_module_can_be_used>

## <first_module_specific_section>

<section_content>

## <second_module_specific_section>

<section_content>

## Parameters

<short_introduction>

- <the_parameters_of_the_module>

## Return values

<short_introduction>

- <the_return_values_of_the_module>

## References

- <the_links>
```

#### Role documentation

The documentation of a (regular, non-ingot) role is a single Markdown file within `docs/` (see [File placement](#file-placement) and [Naming](#naming)). Its content has the following structure:

- The primary heading is the name of the role, derived from the file name.
- A short introduction describing what the role does.
- Any number (possibly zero) of role-specific second-level sections that cover topics applying to the role as a whole rather than to a particular entrypoint.
- One `## Entrypoint: <entrypoint_name>.yml` section for each entrypoint of the role. Each such section consists of:
  - A short introduction describing the entrypoint.
  - A `### Usage` section describing how the entrypoint can be included in a playbook, typically including a complete example.
  - Any number (possibly zero) of entrypoint-specific third-level sections (for example, the prerequisites or the behavior of the entrypoint).
  - A `### Parameters` section consisting of a short introduction (for example, "The entrypoint declares the following inputs") and a list of all inputs of the entrypoint in the format defined in [Parameters and return values](#parameters-and-return-values).
  - A `### Return values` section consisting of a short introduction and a list of all outputs of the entrypoint in the format defined in [Parameters and return values](#parameters-and-return-values). This section is omitted if the entrypoint declares no outputs.
- A `## References` section containing a list of links in the format defined in [References](#references). It is the last section of the file.

The skeleton of the structure is as follows (the `Entrypoint` section is repeated for each entrypoint of the role).

```markdown
# <role_name>

<short_description_of_the_role>

## <first_role_specific_section_not_belonging_to_a_particular_entrypoint>

<section_content>

## <second_role_specific_section_not_belonging_to_a_particular_entrypoint>

<section_content>

## Entrypoint: `<entrypoint_name>.yml`

<short_description_of_the_entrypoint>

### Usage

<how_the_entrypoint_can_be_used>

### <first_entrypoint_specific_section>

<section_content>

### <second_entrypoint_specific_section>

<section_content>

### Parameters

<short_introduction>

- <the_inputs_of_the_entrypoint>

### Return values

<short_introduction>

- <the_outputs_of_the_entrypoint>

## References

- <the_links>
```

#### Ingot role documentation

The documentation of an ingot role is a single Markdown file within `docs/` (see [File placement](#file-placement) and [Naming](#naming)). Its content has the following structure:

- The primary heading is the name of the role, derived from the file name.
- A short introduction describing what the ingot role does and what the ingot it produces does.
- A `## Usage` section describing how the ingot role can be used (that is, how an ingot with it is built and deployed).
- Any number (possibly zero) of ingot role-specific second-level sections between `Usage` and `Parameters`, covering topics that do not fit into the fixed sections (for example, the behavior of the hooks of the role during the build or at boot).
- A `## Parameters` section consisting of a short introduction and exactly two third-level subsections:
  - `### Build` — a short introduction and a list of all parameters the role requires at build time (that is, the parameters of its `install.yml` hook) in the format defined in [Parameters and return values](#parameters-and-return-values).
  - `### Deploy` — a short introduction and a list of all parameters the role requires at deployment time (that is, the union of the parameters of all of its hooks except the `install.yml` hook) in the format defined in [Parameters and return values](#parameters-and-return-values).
- A `## References` section containing a list of links in the format defined in [References](#references). It is the last section of the file.

The skeleton of the structure is as follows.

```markdown
# <role_name>

<short_description_of_the_ingot_role>

## Usage

<how_the_ingot_role_can_be_used>

## <first_ingot_role_specific_section>

<section_content>

## <second_ingot_role_specific_section>

<section_content>

## Parameters

<short_introduction>

### Build

<short_introduction>

- <the_build_time_parameters_of_the_role>

### Deploy

<short_introduction>

- <the_deployment_time_parameters_of_the_role>

## References

- <the_links>
```

#### Parameters and return values

The `Parameters` and `Return values` sections of the documentation of modules, roles and ingot roles list and describe the parameters (inputs) and return values (outputs) of the documented thing, one bullet per entry, using the format defined in this section.

Each entry consists of the name of the parameter or return value, its type, (for parameters) a marker for whether it is required or optional and, if applicable, its default value, and a description of it, in that order; the description is separated from the rest by an em dash (`—`).

For a parameter, the form of the entry depends on whether the parameter is required or optional and whether it has a default value:

```
- `<parameter_name>` (`<parameter_type>`, optional, default `<parameter_default_value>`) — <parameter_description> (the parameter is optional and has a default value)
- `<parameter_name>` (`<parameter_type>`, optional) — <parameter_description> (the parameter is optional and has no default value)
- `<parameter_name>` (`<parameter_type>`, required) — <parameter_description> (the parameter is required)
```

`<parameter_name>` is always the full name of the parameter, not an abbreviated `<placeholder>` form. Within the `<parameter_description>`, however, variables may be referenced using the abbreviated `<placeholder>` form.

The fields of a `dict` parameter are described by appending the name of the field to the name of the parameter with a `.`:

```
- `<parameter_name>` (`dict[str, <value_type>]`, optional, default `<parameter_default_value>`) — <parameter_description> (the `dict` parameter itself)
- `<parameter_name>.<nested_field_name>` (`<parameter_type>`, optional, default `<parameter_default_value>`) — <parameter_description> (a field of the `dict` parameter)
- `<parameter_name>.*.<nested_field_name>` (`<parameter_type>`, required) — <parameter_description> (a field two levels below the parameter, with the name of the intermediate key being unknown/arbitrary)
```

The elements of a `list` parameter are described by appending the index of the element to the name of the parameter with square brackets. The list parameter itself is described with the type of its elements:

```
- `<parameter_name>` (`list[<element_type>]`, required) — <parameter_description> (the `list` parameter itself)
```

If the elements of the list are `dict`s, their fields are described as follows:

```
- `<parameter_name>[*].<nested_field_name>` (`<parameter_type>`, optional, default `<parameter_default_value>`) — <parameter_description> (all elements of the list have the same role/meaning)
- `<parameter_name>[0].<nested_field_name>` (`<parameter_type>`, optional) — <parameter_description> (the first element of the list has a special role/meaning)
- `<parameter_name>[n].<nested_field_name>` (`<parameter_type>`, required) — <parameter_description> (the n-th element of the list has a special role/meaning)
- `<parameter_name>[-1].<nested_field_name>` (`<parameter_type>`, required) — <parameter_description> (the last element of the list has a special role/meaning)
```

The `required`/`optional` marker and the `default` part of the entries for nested fields follow the same rules as for top-level parameters.

The entries for return values are a simplified version of the entries for parameters: they carry only the name, the type, and the description of the return value (the `required`/`optional` marker and the default value do not apply to return values):

```
- `<return_value_name>` (`<return_value_type>`) — <return_value_description>
```

#### References

The `References` section at the end of the documentation of a module, role or ingot role is a bullet list of links to resources that are relevant to the documented thing, for example the documentation, the specification, or the manual pages of a tool, a protocol, or a standard it uses.

Each entry is a link followed by a single sentence describing what is behind the link:

```
- [<link_name>](<url>) — <one_sentence_describing_what_is_behind_the_link>
```

The `References` section of a role (including an ingot role) must include a link to the role's `argument_specs.yml` file, from which the inputs listed in the `Parameters` section are derived.

### Linting

- When an AI agent is asked to `lint` the documentation, it must check all documentation files (that is, the root `AGENTS.md`, `CONTRIBUTING.md` and `README.md` plus everything within `docs/`) for dead links, style, readability and up-to-date information.
- This may be a very expensive operation. The user may also specify that the agent is only to `lint` a specific part of the documentation.
- The `linting` process is responsible for cleaning up the documentation. This includes (partial) restructurings as necessary. Any restructuring must keep `docs/INDEX.md` in sync with the new file locations.
- If the `docs/INDEX.md` file is to be `linted`, the keywords associated with each `index entry` must also be normalized (lowercase, alphabetically sorted, without duplicates).
- If the `linting` process finds a directory within `docs/` that contains exactly one Markdown file and nothing else, it performs the following steps:
  1. Move the file to the parent directory and rename it to `<directory_name>.md`, where `<directory_name>` is the `UPPER_SNAKE_CASE` name of the directory the file currently resides in.
  2. Derive the new primary heading of the file from its new file name (see [Naming](#naming))).
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

### Module and role references

- All references to modules and roles must use the FQN of the module or role (for example, `template` becomes `ansible.builtin.template`).

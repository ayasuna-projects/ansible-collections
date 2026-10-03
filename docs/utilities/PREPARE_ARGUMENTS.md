# Prepare Arguments

The `ayasuna.utilities.prepare_arguments` module prepares arguments: it reads a set of arguments from the variables that are available to a task, validates them against a specification, and returns the validated (and optionally converted) arguments so that subsequent tasks can use them.

The specification is based on the standard Ansible `argument_spec` and is extended by a `context` field which can be used to:

- strip prefixes from the argument names (`context.prefixes`).
- run custom Python code that validates and/or converts the arguments (`context.preparer`).
- define custom validation rules for individual arguments (`context.rules`).

## Usage

The module is used like any other module in a task. Its only parameter, `specification`, holds the (extended) argument specification. For every top-level option of the specification, the module looks up a variable of the same name in the variables that are available to the task (playbook, host, group, task variables, ...). The values of the variables are templated and, if a variable is not set, the default from the specification is used (if the option defines one). The resulting arguments are then validated against the specification.

The module is typically used at the beginning of a playbook or role to collect and validate all of its inputs at once. The module runs on the controller: it never connects to the target system and never changes anything, so `changed` is always `false`. The result is typically registered and the prepared arguments are consumed via the `prepared` key:

```yaml
---
- name: "Prepare the arguments"
  hosts: localhost
  gather_facts: false
  vars:
    hostname: "example.local"
    packages:
      - "curl"
  tasks:
    - name: "Preparing arguments"
      ayasuna.utilities.prepare_arguments:
        specification:
          options:
            hostname:
              type: "str"
              description: "The hostname to set"
              required: true
            packages:
              type: "list"
              description: "The packages to install"
              elements: "str"
              default: []
            ssh:
              type: "dict"
              description: "The SSH settings"
              options:
                port:
                  type: "int"
                  description: "The port the SSH service listens on"
                  default: 22
                allow_root:
                  type: "bool"
                  description: "Whether root may log in via SSH"
                  default: false
      register: demo_arguments

    - name: "Displaying the prepared arguments"
      ansible.builtin.debug:
        msg: "{{ demo_arguments.prepared | to_nice_json }}"
```

In this example the `ssh` variable is not set, so the `ssh` argument is not part of the prepared arguments at all: since the `ssh` option defines neither a `default` nor `apply_defaults: true`, the nested defaults are not applied. If the `ssh` variable were set, the inner fields that are not specified would be filled with their defaults (e.g. setting `ssh` to `{"port": 2222}` would result in `{"port": 2222, "allow_root": false}`).

The `specification` can be provided inline, as in the example above, or as a variable (e.g. loaded from a file) — any expression that evaluates to the specification dictionary is accepted.

The arguments are resolved as follows:

- The top-level option keys of the specification are the names of the variables the module reads.
- An option of type `dict` with `options` must be a variable that is a dictionary whose keys are the sub-option names (recursively). An option of type `list` with `elements: dict` must be a variable that is a list of such dictionaries.
- An argument that is not set is filled with the `default` of the option, if the option defines one.
- For `dict` options, if the variable is set, the inner fields that are not specified are filled with their defaults (regardless of `apply_defaults`). If the variable itself is not set, the nested defaults are only applied when the option has `apply_defaults` set to `true`; otherwise the argument is undefined.
- Only the arguments that are defined in the specification are read. Variables that are not part of the specification are ignored.

The preparation happens in the following order:

1. The arguments are read from the variables (including the defaults).
2. The arguments are validated against the specification.
3. The prefixes (if any) are stripped from the argument names.
4. The custom validation rules (if any) are evaluated.
5. The preparer (if any) validates and converts the arguments.

## Prefixes

The `context.prefixes` field of the specification is a list of string prefixes. After the arguments have been validated, the first prefix that matches the beginning of a top-level argument name is removed. This allows the arguments to be declared with long, unique variable names while the prepared arguments carry only the short names.

This project declares the inputs of roles and playbooks as `<declarer>__inputs__<name>` (see [CONTRIBUTING.md](../../CONTRIBUTING.md) for the full naming convention). The inputs of a role with the FQN `demo.collection.role` are therefore declared as `demo__collection__role__inputs__<name>`:

```yaml
---
- name: "Prepare the arguments of a role"
  hosts: localhost
  gather_facts: false
  vars:
    demo__collection__role__inputs__hostname: "example.local"
    demo__collection__role__inputs__mtu: 1400
  tasks:
    - name: "Preparing arguments"
      ayasuna.utilities.prepare_arguments:
        specification:
          context:
            prefixes:
              - "demo__collection__role__inputs__"
          options:
            demo__collection__role__inputs__hostname:
              type: "str"
              description: "The hostname to set"
              required: true
            demo__collection__role__inputs__mtu:
              type: "int"
              description: "The MTU to use"
              default: 1500
      register: demo_arguments

    - name: "Displaying the prepared arguments"
      ansible.builtin.debug:
        msg: "{{ demo_arguments.prepared | to_nice_json }}"
```

The prepared arguments then contain only the short names:

```json
{"hostname": "example.local", "mtu": 1400}
```

- If multiple prefixes are listed, the first prefix in the list that matches a name wins.
- Names that do not match any prefix are left unchanged.
- Only the top-level names are affected; the names of the sub-options are never prefixed.
- The rules and the preparer operate on the arguments *after* the prefixes have been stripped, so they reference the short names.

## Rules

Individual arguments can be validated with custom rules that go beyond what the standard `argument_spec` offers — most importantly, relationships between different arguments. Rules are defined in the `context` field of an option and consist of a list of entries, each with two fields:

- `expression` — a Jinja2 expression that must evaluate to a boolean.
- `message` — the error message that is reported if the expression evaluates to `false`.

Rules can be attached to any option at any nesting level. The expressions are evaluated after the prefixes have been stripped and only provide two variables:

- `arguments` — the full set of prepared (top-level) arguments, referenced by the short names.
- `indices` — the list of indices that are required to access the current value, starting at the top level of the arguments. It is empty for options that are not contained in a `list` (e.g. top-level options and the sub-options of top-level `dict` options). To reference the current element of a list, use `arguments.<option>[indices[0]]`; for a value nested in two lists, the path would be something like `arguments.users[indices[0]].groups[indices[1]].name`.

A rule that is attached to an option is evaluated:

- once, if the option is a top-level option or a sub-option of a `dict` value,
- once per element, if the option is a sub-option of an element of a `list` value with `elements: dict` — in this case `indices` contains one index per enclosing `list`, from the outermost to the innermost.

If the expression evaluates to `false`, the corresponding `message` is reported as an error and the task fails. If the expression cannot be evaluated, or if it does not result in a boolean, this is also reported as an error.

```yaml
---
- name: "Prepare the arguments with custom validation rules"
  hosts: localhost
  gather_facts: false
  vars:
    demo__collection__role__inputs__users:
      - name: "root"
        password: "secret"
      - name: "alice"
        password: "password123"
  tasks:
    - name: "Preparing arguments"
      ayasuna.utilities.prepare_arguments:
        specification:
          context:
            prefixes:
              - "demo__collection__role__inputs__"
          options:
            demo__collection__role__inputs__users:
              type: "list"
              description: "The users to configure"
              required: true
              elements: "dict"
              context:
                rules:
                  - expression: "(arguments.users | length) > 0"
                    message: "At least one user must be specified"
                  - expression: "(arguments.users | selectattr('name', 'equalto', 'root') | list | length) == 1"
                    message: "The root user must be specified"
              options:
                name:
                  type: "str"
                  description: "The user name"
                  required: true
                  context:
                    rules:
                      - expression: "indices[0] != 0 or arguments.users[indices[0]].name == 'root'"
                        message: "The first user must be root"
                password:
                  type: "str"
                  description: "The user password"
                  required: true
      register: demo_arguments

    - name: "Displaying the prepared arguments"
      ansible.builtin.debug:
        msg: "{{ demo_arguments.prepared | to_nice_json }}"
```

If, for example, the first user was not `root`, the task would fail with the error message `The first user must be root`.

## Preparers

The `context.preparer` field of the specification is a string containing Python 3 code. The code is executed on the controller (not on the target system) in an isolated namespace and may define two functions:

- `validate(arguments: dict) -> list[str]` — validates the arguments and returns a list of error messages. If the list is not empty, the preparation fails with these errors.
- `convert(arguments: dict) -> dict` — converts the arguments and returns the new set of arguments. The returned dictionary becomes the prepared arguments.

The functions receive the arguments *after* the prefixes have been stripped and the rules have been evaluated. `validate` (if defined) is executed before `convert` (if defined). If neither function is defined, the arguments are passed through unchanged. Standard library modules (e.g. `import copy`) may be imported in the code.

```yaml
---
- name: "Prepare the arguments with a custom preparer"
  hosts: localhost
  gather_facts: false
  vars:
    demo__collection__role__inputs__host: "Example.Local"
    demo__collection__role__inputs__port: 8080
  tasks:
    - name: "Preparing arguments"
      ayasuna.utilities.prepare_arguments:
        specification:
          context:
            prefixes:
              - "demo__collection__role__inputs__"
            preparer: |
              def validate(arguments: dict) -> list:
                  if "." not in arguments["host"]:
                      return ["The host must be a FQDN (e.g. 'example.local')"]

                  return []


              def convert(arguments: dict) -> dict:
                  result = dict(arguments)
                  result["endpoint"] = f"{result['host'].lower()}:{result['port']}"
                  return result
          options:
            demo__collection__role__inputs__host:
              type: "str"
              description: "The host"
              required: true
            demo__collection__role__inputs__port:
              type: "int"
              description: "The port"
              required: true
      register: demo_arguments

    - name: "Displaying the prepared arguments"
      ansible.builtin.debug:
        msg: "{{ demo_arguments.prepared | to_nice_json }}"
```

The prepared arguments then contain the additional `endpoint` argument (`example.local:8080`).

## Parameters

The module accepts a single parameter, `specification`, which is an extended Ansible argument specification. The parameter and its fields are:

- `specification` (`dict[str, str | dict]`, required) — the (extended) argument specification. The top-level `options` and `context` keys are described below; other keys of the specification (e.g. `short_description`) are ignored by the module.
- `specification.options` (`dict[str, dict]`, optional, default `{}`) — the standard Ansible argument specification options. The top-level keys of `options` are the names of the variables the module reads from the variables that are available to the task. Every option supports the standard `argument_spec` fields (`type`, `description`, `required`, `default`, `choices`, `elements`, `options`, `apply_defaults`, ...); see the [References](#references) section for the full list of fields.
- `specification.options.*.context` (`dict[str, list]`, optional) — the context of an individual option. The `*` matches the name of any option; because options of type `dict` and of type `list` with `elements: dict` may define their own `options`, this applies recursively to options at any nesting level.
- `specification.options.*.context.rules` (`list[dict]`, optional) — the custom validation rules for the option. See [Rules](#rules).
- `specification.options.*.context.rules[*].expression` (`str`, required) — a Jinja2 expression that must evaluate to a boolean.
- `specification.options.*.context.rules[*].message` (`str`, required) — the error message that is reported if the expression evaluates to `false`.
- `specification.context` (`dict[str, str | list[str]]`, optional) — the context of the specification.
- `specification.context.prefixes` (`list[str]`, optional, default `[]`) — the prefixes that are stripped from the argument names. See [Prefixes](#prefixes).
- `specification.context.preparer` (`str`, optional) — the Python 3 code that validates and/or converts the arguments. See [Preparers](#preparers).

## Return values

If the preparation succeeds, the result contains:

- `prepared` (`dict`) — the prepared arguments. The keys are the (prefix-stripped) option names and the values are the validated and (optionally) converted values.
- `hash` (`str`) — a stable MD5 hash (hex digest) of the prepared arguments serialized as JSON with sorted keys. The hash changes only if the content of the prepared arguments changes, which makes it suitable for detecting changes between runs (e.g. for caching).
- `specification` (`dict`) — the specification as it was passed to the module.
- `changed` (`bool`) — always `false`. The module only prepares arguments and never changes anything.
- `msg` (`str`) — a human-readable status message.

If the preparation fails, the task fails and the result contains:

- `changed` (`bool`) — `false`.
- `failed` (`bool`) — `true`.
- `errors` (`list[str]`) — the individual error messages from the argument validation, the rules, and/or the preparer.
- `msg` (`str`) — a message that lists all of the errors.

## References

- [Argument specification (Ansible documentation)](https://docs.ansible.com/ansible/latest/dev_guide/developing_program_flow_modules.html#argument-spec) — Describes the standard fields (types, defaults, choices, nested options, ...) that are supported by the `options` part of the specification.
- [Templating (Jinja2) (Ansible documentation)](https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_templating.html) — Describes the Jinja2 templating in Ansible, which is used within the rule expressions.
- [Python 3 documentation](https://docs.python.org/3/) — The language reference for the code that is used in `context.preparer`.

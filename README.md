# Readme

This project contains Ansible collections.

## Quickstart

The collections provided in this repository — and the modules and roles they contain — can be installed from the git repository
with `ansible-galaxy install` and a `requirements.yml` file.

Create a `requirements.yml` file with the following content.

```yaml
---
collections:
  - name: "git@github.com:ayasuna-projects/ansible-collections.git#/collections/"
    type: "git"
    version: "main"
```

Then install the collections.

```bash
ansible-galaxy install -r requirements.yml
```

This installs the `ayasuna.ingot` and `ayasuna.utilities` collections from the `main` branch of the repository. For
more information on installing collections with a requirements file, see
the [Ansible documentation](https://docs.ansible.com/projects/ansible/latest/collections_guide/collections_installing.html#install-multiple-collections-with-a-requirements-file).

## Documentation

- [CONTRIBUTING.md](CONTRIBUTING.md) — contribution guidelines (documentation, code style)
- [docs/INDEX.md](docs/INDEX.md) — index of the project documentation

### Reading the documentation

Throughout the prose of the documentation, placeholders are written in the form of `<name>`, as specified in
[CONTRIBUTING.md](CONTRIBUTING.md#placeholder).

In the documentation of roles, they stand either for the role's input variables, abbreviated by dropping the
`<declarer>__inputs__` prefix, or for the role's return values (output variables), abbreviated by dropping the
`<declarer>__outputs__` prefix, or for ordinary placeholders that do not refer to a variable —
see [CONTRIBUTING.md](CONTRIBUTING.md#variable-naming) for the naming convention of variables.

In the remaining documentation (e.g. for modules), placeholders are always ordinary ones.

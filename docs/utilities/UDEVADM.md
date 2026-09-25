# Udevadm

The `ayasuna.utilities.udevadm` role performs a few `udevadm` operations on the host it runs on: it reloads the UDEV ruleset, optionally triggers device events so that the (re)loaded rules are applied to existing devices, and waits for the UDEV event queue to become empty.

The role does not create or modify UDEV rules files. It expects the rules files (typically in `/etc/udev/rules.d/`) to already exist and makes the running `udevd` daemon pick them up.

## Usage

The role is used like any other role by including it in a play. Its inputs are declared as variables following the pattern `ayasuna__utilities__udevadm__inputs__<name>`:

```yaml
---
- name: "Reload the UDEV ruleset and re-trigger the network devices"
  hosts: "targets"
  gather_facts: false
  tasks:
    - name: "Including the 'ayasuna.utilities.udevadm' role"
      ansible.builtin.include_role:
        name: "ayasuna.utilities.udevadm"
      vars:
        ayasuna__utilities__udevadm__inputs__reload: true
        ayasuna__utilities__udevadm__inputs__trigger:
          - action: "add"
            type: "devices"
            match_subsystem: "net"
        ayasuna__utilities__udevadm__inputs__settle_timeout: 30
```

In this example the role reloads the UDEV ruleset, triggers an `add` event for all devices of the `net` subsystem (so that the new rules are applied to the existing network devices), and then waits up to 30 seconds for the UDEV event queue to become empty.

All inputs have defaults, so the role can also be included without any variables:

```yaml
- name: "Including the 'ayasuna.utilities.udevadm' role with the default inputs"
  ansible.builtin.include_role:
    name: "ayasuna.utilities.udevadm"
```

With the defaults, the role reloads the UDEV ruleset, does not trigger any events, and waits up to 30 seconds for the UDEV event queue to become empty.

The tasks of the role run on the host the play is connected to, so the role must be run against the host on which the `udevd` daemon runs (normally the target host itself). That host must provide the `udevadm` binary (available on Linux systems with systemd/udev) and the user running the tasks must be allowed to communicate with the `udevd` daemon (typically root).

## Operations

The role performs the following operations in this order:

1. **Reload** — `udevadm control --reload` (when `reload` is `true`). Signals the running `udevd` daemon to reload the rules files and other databases (such as the kernel module index). Reloading does not apply any changes to already existing devices; the new configuration only takes effect for subsequent events, which is the purpose of the trigger step.
2. **Trigger** — one `udevadm trigger --verbose --action=<action> --type=<type> --subsystem-match=<subsystem>` command per entry of `trigger` (in list order). Requests device events from the kernel, causing the reloaded rules to be (re)applied to the existing devices.
3. **Settle** — `udevadm settle --timeout=<settle_timeout>` (when `settle_timeout` is greater than `0`). Waits until the UDEV event queue is empty, so that subsequent tasks can rely on the triggered events having been fully processed.

## Triggers

Each entry of `trigger` corresponds to a single invocation of `udevadm trigger`. The entries are executed in the order they are listed. Every entry consists of three fields, all of which are required:

- `action` — the event type to be triggered. One of `add`, `remove`, `change`, `move`, `online`, `offline`, `bind`, `unbind`.
- `type` — the type of device to trigger. Either `devices` or `subsystems`.
- `match_subsystem` — triggers events only for the devices matching the given subsystem. Currently only `net` is supported.

## Settle

`settle_timeout` is the timeout in seconds for the `udevadm settle` command:

- The default is `30`.
- A value of `0` skips the `udevadm settle` step entirely.
- If the UDEV event queue is not empty when the timeout is reached, the role does **not** fail; there is no guarantee that the queue is empty after the timeout. Tasks that run after the role should therefore tolerate events that are still being processed, if necessary.

## Parameters

The authoritative source for the parameter definitions of the role is its argument spec: [argument_specs.yml](../../collections/utilities/roles/udevadm/meta/argument_specs.yml).

The role declares the following inputs (declared with the `ayasuna__utilities__udevadm__inputs__` prefix):

- `ayasuna__utilities__udevadm__inputs__reload` (bool, default `true`) — whether to reload the UDEV ruleset (`udevadm control --reload`).
- `ayasuna__utilities__udevadm__inputs__trigger` (list of dicts, default `[]`) — the `udevadm trigger` commands to execute to apply the UDEV ruleset changes. See [Triggers](#triggers).
- `ayasuna__utilities__udevadm__inputs__settle_timeout` (int, default `30`) — the timeout in seconds of the `udevadm settle` command. See [Settle](#settle).

## References

- [udevadm(8) (man page)](https://www.kernel.org/pub/linux/utils/kernel/hotplug/udev/udevadm.html) — Documents the `udevadm` tool and the `control`, `trigger`, and `settle` commands that the role wraps.
- [udev(7) (man page)](https://www.kernel.org/pub/linux/utils/kernel/hotplug/udev/udev.html) — Documents udev and its rules files, which the role reloads and applies.

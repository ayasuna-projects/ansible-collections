# Rescue

The `ayasuna.ingot.rescue` role is an [ingot](../utilities/INGOT.md) role for a simple rescue system. The ingot it
produces is primarily intended to be written to a USB stick (via the [`deploy.yml` entrypoint of the
`ayasuna.utilities.ingot` role](../utilities/INGOT.md#entrypoint-deployyml)) from which a (U)EFI host can boot
into the rescue system — for example, to administer or repair a host.

A booted rescue system is a minimal Debian system that, on every boot, configures a hostname and a set of users
(each non-root user with passwordless `sudo`), sets up SSH access via public-key authentication, DHCP-based
networking, and a locked-down firewall.

## Usage

The role is an ingot role: it is not included directly in a playbook. Instead, it is built into an ingot via the
[`build.yml` entrypoint of the `ayasuna.utilities.ingot` role](../utilities/INGOT.md#entrypoint-buildyml), and the
resulting ingot is written to a block device — typically a USB stick — via the `deploy.yml` entrypoint of the same
role. A (U)EFI host can then boot from that device into the ingot.

The overall workflow is as follows:

1. **Build** — build the ingot, with `ayasuna.ingot.rescue` as the ingot role.
2. **Deploy** — write the ingot to a USB stick, passing the role's inputs (the hostname and the users) as
   deployment arguments.
3. **Boot** — boot the (U)EFI host from the USB stick.

The role's inputs (`<name>` and `<users>`) can be provided at build time (embedded into the ingot) or at
deployment time (stored with each deployment). The latter is typically preferred for a USB-stick-based rescue
system: the ingot is built once and then deployed to multiple sticks or hosts, each with its own hostname and
users. If an input is given both at build time and at deployment time, the deployment value takes precedence.

### Build

The example below builds the rescue ingot on the local machine via the `build.yml` entrypoint of the
`ayasuna.utilities.ingot` role. The entrypoint's prerequisites (e.g. the packages the build host must provide) and
its inputs are documented [there](../utilities/INGOT.md#entrypoint-buildyml):

```yaml
# Builds the rescue ingot
- name: "Build rescue ingot"
  hosts:
    - "localhost"
  # The example assumes that the host the ingot is built on is the local machine
  connection: "local"
  serial: 1
  gather_facts: false
  vars:
    # The operating system to use as the base of the ingot
    ayasuna__utilities__ingot__inputs__build_operating_system: "debian:13-amd64"
    # The root password set during the OS installation; it may differ from the password the ingot configures during its boot process
    ayasuna__utilities__ingot__inputs__build_users_root_password: "some-root-pw"
    # The Ansible collections to install into the ingot; must include the collection containing the ingot role (here: this repository)
    ayasuna__utilities__ingot__inputs__build_ansible_collections:
      - name: "git@github.com:ayasuna-projects/ansible-collections.git#/collections/"
        type: "git"
        version: "main"
    # The ingot role that provides the hooks
    ayasuna__utilities__ingot__inputs__build_ansible_role_fqn: "ayasuna.ingot.rescue"
    # No inputs are embedded into the ingot: they are provided at deployment time (see "Deploy rescue ingot" below)
    ayasuna__utilities__ingot__inputs__build_ansible_role_arguments: { }
    # The directory in which the build process puts its temporary files
    ayasuna__utilities__ingot__inputs__working_directory: "/tmp/build_rescue_ingot/"
    ayasuna__utilities__ingot__inputs__qemu_accelerator: "kvm"
    # If true, QEMU runs in headless mode (no GUI)
    ayasuna__utilities__ingot__inputs__qemu_headless: false
    # These OVMF firmware files are provided by the 'ovmf' package and must be present on the build host
    ayasuna__utilities__ingot__inputs__qemu_efi_code: "/usr/share/OVMF/OVMF_CODE_4M.fd"
    ayasuna__utilities__ingot__inputs__qemu_efi_vars: "/usr/share/OVMF/OVMF_VARS_4M.fd"
    # The location of the resulting ingot; a local path here because the ingot is built locally
    ayasuna__utilities__ingot__inputs__target_file: "{{ playbook_dir }}/../artifacts/rescue.amd64.squashfs"
    # The inputs the ingot's hooks are called with when the ingot is tested in the test VM
    ayasuna__utilities__ingot__inputs__test_arguments:
      # The hostname the ingot configures at boot during the test
      ayasuna__ingot__rescue__inputs__name: "rescue01"
      # The users the ingot sets up at boot during the test; each non-root user can use passwordless 'sudo'
      ayasuna__ingot__rescue__inputs__users:
        - name: "root" # required for the rescue ingot
          password: "<root_password>"
          # Public keys for the root user have no effect for the rescue ingot, as it does not allow SSH access via root
          public_keys: [ ]
        - name: "<your_username>"
          password: "<your_password>"
          public_keys:
            - name: "<your_key_name>"
              content: "<your_public_key>"
              type: "ssh-ed25519"
    # If the ingot uses DHCP (as the rescue ingot does), the test VM gets the IPv4 address ending in .15 of the test network
    ayasuna__utilities__ingot__inputs__test_ssh_ip: "10.111.0.15"
    ayasuna__utilities__ingot__inputs__test_ssh_port: 22
    ayasuna__utilities__ingot__inputs__test_ssh_username: "<your_username>"
    # The private key matching the public key above (<your_public_key>)
    ayasuna__utilities__ingot__inputs__test_ssh_private_key: "<your_private_key>"
    ayasuna__utilities__ingot__inputs__test_interfaces:
      - mac: "1e:0e:d6:f7:29:b2"
        ipv4_cidr: "10.111.0.0/24"
    ayasuna__utilities__ingot__inputs__test_disks_additional: [ ]
  tasks:
    - ansible.builtin.import_role:
        name: "ayasuna.utilities.ingot"
        tasks_from: "build.yml"
```

In this example the ingot is built without any embedded inputs — the hostname and users are instead provided at
deployment time — and the resulting ingot is written to `{{ playbook_dir }}/../artifacts/rescue.amd64.squashfs`.

### Deploy

The example below deploys the rescue ingot to the USB stick that is plugged into the local machine, via the
`deploy.yml` entrypoint of the `ayasuna.utilities.ingot` role. The entrypoint's prerequisites and inputs are
documented [there](../utilities/INGOT.md#entrypoint-deployyml):

```yaml
# Deploys the rescue ingot to a USB stick
- name: "Deploy rescue ingot"
  hosts:
    - "localhost"
  # The example assumes that the USB stick is plugged into the local machine
  connection: "local"
  serial: 1
  gather_facts: false
  vars:
    # The previously built ingot (from the "Build rescue ingot" playbook above)
    ayasuna__utilities__ingot__inputs__source_ingot: "{{ playbook_dir }}/../artifacts/rescue.amd64.squashfs"
    # The inputs the ingot's hooks are called with when the host boots into the ingot
    ayasuna__utilities__ingot__inputs__source_arguments:
      # The hostname the ingot configures at boot
      ayasuna__ingot__rescue__inputs__name: "rescue01"
      # The users the ingot sets up at boot; each non-root user can use passwordless 'sudo'
      ayasuna__ingot__rescue__inputs__users:
        - name: "root" # required for the rescue ingot
          password: "<root_password>"
          # Public keys for the root user have no effect for the rescue ingot, as it does not allow SSH access via root
          public_keys: [ ]
        - name: "<your_username>"
          password: "<your_password>"
          public_keys:
            - name: "<your_key_name>"
              content: "<your_public_key>"
              type: "ssh-ed25519"
    # The USB stick to write the ingot to; it must exist and must not contain any partitions
    ayasuna__utilities__ingot__inputs__target_device_path: "/dev/sdb"
    # The size in MiB of the partition that holds the ingot deployments; the remaining space of the device is used for the "DATA" partition
    ayasuna__utilities__ingot__inputs__target_partitions_deployment_size: 8192
    # How many ingot deployments to keep (including the current one), at least one
    ayasuna__utilities__ingot__inputs__target_partitions_deployment_history: 1
  tasks:
    - ansible.builtin.import_role:
        name: "ayasuna.utilities.ingot"
        tasks_from: "deploy.yml"
```

In this example the role writes the rescue ingot (built by the `Build rescue ingot` playbook above) to `/dev/sdb`
— the USB stick — together with the deployment arguments (the hostname and the users), keeps a single deployment,
and installs the GRUB bootloader on the stick. On first use, the entrypoint partitions the device (into a `BOOT`,
a `DEPLOYMENT`, and a `DATA` partition); see [the `Behavior` section of the `deploy.yml` entrypoint](../utilities/INGOT.md#behavior-1)
for the full sequence of operations.

The GRUB bootloader is installed into the well-known removable (U)EFI directory (`/EFI/BOOT/`), so the stick can
be used to boot any (U)EFI host — not only the machine it was written on. No reboot of the machine is required;
the ingot is ready as soon as a host boots from the stick into the ingot.

### Boot

Boot the (U)EFI host from the USB stick (select the stick in the host's (U)EFI boot menu). The host starts GRUB,
which loads the most recently deployed ingot by default (earlier deployments remain available in the boot menu
as long as they have not been removed by a newer deployment).

## Behavior

All hooks validate their inputs against the role's argument specification (see [Parameters](#parameters)) before
doing anything else; if the validation fails, the hook fails.

**`install.yml`** — called once during the build. Performs a system upgrade (via APT, including an update of the
package lists and the removal of no-longer-needed packages, purging their configuration) and installs a fixed set
of default packages (via the [`packages.yml` entrypoint of the `ayasuna.utilities.host`
role](../utilities/HOST.md#entrypoint-packagesyml)): `openssh-server`, `nftables`, `sudo`, `htop`, `iotop`, `nload`,
`parted`, `iproute2`, `dnsutils`, `curl`, `bash-completion`, and `grep`. Declares no inputs.

**`local.yml`** — called on every boot, before networking. Performs the following, in order:

1. Sets the system hostname to `<name>` (manages `/etc/hostname`, the running hostname, and `/etc/hosts`).
2. Sets up the users given in `<users>` (see [Users and SSH](#users-and-ssh)).
3. Writes the firewall configuration (see [Firewall](#firewall)).
4. Writes the network configuration (see [Network](#network)).

**`network.yml`** and **`final.yml`** — called on every boot. Validate their inputs and perform no further
actions.

**`test.yml`** — called once in the test VM during the build. Validates its inputs and performs no further
actions.

## Users and SSH

`<users>` must contain at least one user, and the `root` user exactly once.

For each user in `<users>`, the `local.yml` hook performs the following on every boot (via the [`users.yml`
entrypoint of the `ayasuna.utilities.host` role](../utilities/HOST.md#entrypoint-usersyml)):

1. **Account** — creates (or updates) the user account with a login shell of `/bin/bash` and a home directory;
   the password is set (as a SHA-512 hash) on every run.
2. **SSH keys** — if the user has one or more public keys, the user's `~/.ssh/authorized_keys` file is managed
   **exclusively**: it contains exactly the given keys (one per line, in the form `<key_type> <key_content>
   <key_name>`), and any other keys are removed. The `~/.ssh` directory is managed as well.
3. **Sudo** — for every user except `root`, the file `/etc/sudoers.d/00-<user_name>` (mode `0440`, owned by
   `root:root`) is written, granting the user passwordless `sudo` (`<user_name> ALL=(ALL:ALL) NOPASSWD:ALL`).

The SSH service is enabled in the ingot (set up during the build) with a hardened configuration: it listens on
port `22` (on all interfaces, IPv4 and IPv6), uses only public-key authentication (password authentication is
disabled), and denies root login. Therefore:

- The public keys of the `root` entry in `<users>` have no effect.
- To administer the system, connect via SSH as a non-root user (using one of their public keys) and use `sudo`
  to become `root`.
- The SSH host keys are generated during the build and baked into the ingot: all hosts that boot into the same
  ingot share the same host keys, and a new build produces new host keys (which may cause an SSH client to refuse
  to connect until the old keys are removed from the `known_hosts` file).

## Network

The `local.yml` hook writes the file `/etc/systemd/network/00-ethernet.network`, which the network manager
applies to all `en*` interfaces:

- **IPv4** — the interface obtains its address via DHCP.
- **IPv6** — the interface obtains a link-local address (EUI-64) and accepts router advertisements (SLAAC). The
  host does not send router advertisements itself, and the IPv6 privacy extensions are disabled.
- **DNS** — the nameservers are obtained from the network (via DHCPv4/IPv6 RA) and used by `systemd-resolved`;
  LLMNR, mDNS, DNSSEC, and DNS-over-TLS are disabled.

The role does not support static address configuration: the rescue system's addresses are always obtained from
the attached network.

## Firewall

The `local.yml` hook writes the nftables configuration to `/etc/nftables.conf` on every boot (via the
[`firewall.yml` entrypoint of the `ayasuna.utilities.host` role](../utilities/HOST.md#entrypoint-firewallyml));
the `nftables` service (enabled in the ingot) loads the file at boot after the hook has run. The generated
configuration uses the following presets and no custom rules:

- `filter@log` — logs packets that hit the default policy of the filter base chains (rate-limited to 20 per
  minute).
- `filter@input.default` — applies sane default input rules: accepts packets that belong to an existing flow,
  drops invalid packets, accepts valid loopback traffic (and drops invalid loopback traffic), and allows safe
  ICMP/ICMPv6 packets (especially for IPv6, per RFC 4890).
- `filter@input.ssh` — accepts all SSH input traffic on port 22.

The resulting policies are:

- **Input** — policy `drop`: only established flows, loopback traffic, safe ICMP/ICMPv6, and SSH on port 22 are
  accepted.
- **Forward** — policy `drop`: no traffic is forwarded (the rescue system is not a router).
- **Output** — policy `accept`.

## Parameters

The `local.yml`, `network.yml`, `final.yml`, and `test.yml` entrypoints of the role declare the following inputs
(all using the prefix `ayasuna__ingot__rescue__inputs__`). The `install.yml` entrypoint declares no inputs.

- `ayasuna__ingot__rescue__inputs__name` (`str`, required) — the hostname to set on the system.
- `ayasuna__ingot__rescue__inputs__users` (`list[dict]`, required) — the users to set up/configure. At least one
  user must be specified, and the `root` user exactly once. All users (except for `root`) will be able to become
  `root` by using `sudo`.
- `ayasuna__ingot__rescue__inputs__users[*].name` (`str`, required) — the user name.
- `ayasuna__ingot__rescue__inputs__users[*].password` (`str`, required) — the password of the user.
- `ayasuna__ingot__rescue__inputs__users[*].public_keys` (`list[dict]`, required) — the public keys to set up
  for the user (placed in the user's `~/.ssh/authorized_keys` file).
- `ayasuna__ingot__rescue__inputs__users[*].public_keys[*].name` (`str`, required) — the name of the public key.
- `ayasuna__ingot__rescue__inputs__users[*].public_keys[*].content` (`str`, required) — the contents of the
  public key.
- `ayasuna__ingot__rescue__inputs__users[*].public_keys[*].type` (`str`, required) — the public key type. One
  of: `ecdsa-sha2-nistp521`, `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp256`, `ssh-ed25519`, `ssh-rsa`.

## References

- [argument_specs.yml](../../collections/ingot/roles/rescue/meta/argument_specs.yml) — the argument
  specification of the role, from which the inputs listed in the Parameters section are derived.
- [INGOT.md](../utilities/INGOT.md) — the documentation of the `ayasuna.utilities.ingot` role, whose `build.yml`
  and `deploy.yml` entrypoints are used to build and deploy the rescue ingot.
- [HOST.md](../utilities/HOST.md) — the documentation of the `ayasuna.utilities.host` role, whose `packages.yml`,
  `users.yml`, and `firewall.yml` entrypoints the rescue ingot uses during the build and at boot.
- [systemd.network(5) (man page)](https://manpages.debian.org/stable/systemd/systemd.network.5.en.html) — the
  format of the `.network` file that the `local.yml` hook writes.

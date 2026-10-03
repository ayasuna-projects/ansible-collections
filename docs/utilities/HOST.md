# Host

The `ayasuna.utilities.host` role manages various aspects of a Debian-based host system. The role
has no default entrypoint: each entrypoint must be included explicitly via `tasks_from`. All entrypoints are expected to
be run on
the target host as `root` (for example via `become: true`), and all of their inputs are declared as variables
using the prefix `ayasuna__utilities__host__inputs__`.

The entrypoints are:

- `packages.yml` — upgrades the system and installs packages.
- `hostname.yml` — sets the system's hostname.
- `ssh.yml` — configures the SSH service.
- `volume.yml` — sets up and manages a single data volume.
- `firewall.yml` — creates or replaces the nftables firewall configuration without applying it.
- `users.yml` — sets up users.

## Entrypoint: `packages.yml`

Upgrades the system and installs packages.

### Usage

```yaml
---
- name: "Upgrading the system and installing packages"
  hosts: "targets"
  gather_facts: false
  become: true
  tasks:
    - name: "Including the 'ayasuna.utilities.host' role (packages.yml)"
      ansible.builtin.include_role:
        name: "ayasuna.utilities.host"
        tasks_from: "packages.yml"
      vars:
        ayasuna__utilities__host__inputs__packages:
          - "nfs-common"
          - "python3-kubernetes"
```

### Behavior

The entrypoint uses `ansible.builtin.apt` to perform the following steps, in order:

1. **Update** the APT package lists.
2. **Upgrade** all installed packages (a distribution upgrade).
3. **Autoremove** packages that are no longer needed, purging their configuration.
4. **Install** a fixed set of default packages: `openssh-server`, `sudo`, `nftables`, `htop`, `iotop`,
   `nload`, `parted`, `iproute2`, `dnsutils`, `curl`, `bash-completion`, and `grep`.
5. **Install** the additional packages listed in `<packages>` (if any).

### Parameters

The entrypoint declares the following inputs:

- `ayasuna__utilities__host__inputs__packages` (`list[str]`, optional, default `[]`) — the packages in addition
  to the default packages to install.

## Entrypoint: `hostname.yml`

Sets the system's hostname.

### Usage

```yaml
---
- name: "Setting the system's hostname"
  hosts: "targets"
  gather_facts: false
  become: true
  tasks:
    - name: "Including the 'ayasuna.utilities.host' role (hostname.yml)"
      ansible.builtin.include_role:
        name: "ayasuna.utilities.host"
        tasks_from: "hostname.yml"
      vars:
        ayasuna__utilities__host__inputs__hostname: "my-host.example.com"
```

### Behavior

The entrypoint manages the following:

- `/etc/hostname` — replaced with a file containing only `<hostname>`.
- The running hostname — set by writing `<hostname>` to `/proc/sys/kernel/hostname`. The entrypoint deliberately
  does not use `hostnamectl` (or `ansible.builtin.hostname`), because it may be called very early in the boot
  process, at which point those commands can fail.
- `/etc/hosts` — replaced with a static file mapping `127.0.1.1` to `<hostname>` (in addition to the standard
  `localhost`, `ip6-localhost`, `ip6-allnodes`, and `ip6-allrouters` entries).

### Parameters

The entrypoint declares the following inputs:

- `ayasuna__utilities__host__inputs__hostname` (`str`, required) — the hostname to set.

## Entrypoint: `ssh.yml`

Configures the SSH service.

### Usage

```yaml
---
- name: "Configuring the SSH service"
  hosts: "targets"
  gather_facts: false
  become: true
  tasks:
    - name: "Including the 'ayasuna.utilities.host' role (ssh.yml)"
      ansible.builtin.include_role:
        name: "ayasuna.utilities.host"
        tasks_from: "ssh.yml"
      vars:
        ayasuna__utilities__host__inputs__host_key_directory: "/etc/ssh"
```

### Behavior

The entrypoint manages the following:

- `<host_key_directory>` — created (mode `0755`, owned by `root:root`) if it doesn't exist.
- The host keys — three host keys are generated in `<host_key_directory>` using `ssh-keygen`, each **only if it
  doesn't already exist** (existing keys are never overwritten or rotated):
    - `ssh_host_rsa_key` — an RSA key with 8192 bits.
    - `ssh_host_ecdsa_key` — an ECDSA key with 521 bits.
    - `ssh_host_ed25519_key` — an Ed25519 key.

  All keys are generated without a passphrase.
- `/etc/ssh/sshd_config` — replaced with a hardened configuration that listens on port `22` (on all interfaces,
  IPv4 and IPv6), uses the three host keys above, enables only public-key authentication (disabling password,
  challenge-response, Kerberos, and GSSAPI authentication and empty passwords), disallows root login, limits
  `LoginGraceTime` to `2m`, `MaxAuthTries` to `6`, and `MaxSessions` to `10`, disables X11 forwarding, and
  enables the `sftp` subsystem.

The entrypoint does not restart or reload the `sshd` service; the new host keys and configuration take effect the
next time the service is (re)started.

### Parameters

The entrypoint declares the following inputs:

- `ayasuna__utilities__host__inputs__host_key_directory` (`str`, required) — the path to the directory in which
  the host keys should be placed. It is created if it doesn't exist.

## Entrypoint: `volume.yml`

Sets up and manages a single data volume.

### Usage

```yaml
---
- name: "Setting up a data volume"
  hosts: "targets"
  gather_facts: false
  become: true
  tasks:
    - name: "Including the 'ayasuna.utilities.host' role (volume.yml)"
      ansible.builtin.include_role:
        name: "ayasuna.utilities.host"
        tasks_from: "volume.yml"
      vars:
        ayasuna__utilities__host__inputs__device_serial: "SN00000001"
        ayasuna__utilities__host__inputs__partition_name: "data"
        ayasuna__utilities__host__inputs__filesystem_type: "ext4"
        ayasuna__utilities__host__inputs__mount_target: "/data"
```

### Behavior

The entrypoint performs the following steps, in order:

1. **Identify the device** — (best effort) waits for the UDEV event queue to settle, then runs `lsblk` to find
   the block device whose serial number matches `<device_serial>` (generally a whole disk or drive).
2. **Partition** — creates a GPT partition table on the device with a single partition spanning the whole
   device, named `<partition_name>` (via `community.general.parted`).
3. **Filesystem** — creates a `<filesystem_type>` filesystem on the partition, addressed via its partition UUID
   (`/dev/disk/by-partuuid/<uuid>`, via `community.general.filesystem`). The filesystem is created only if the
   partition doesn't already have one: existing filesystems are **neither reformatted nor resized**.
4. **Mount target** — creates the directory `<mount_target>` (mode `0755`, owned by `root:root`) if it doesn't
   exist.
5. **Mount unit** — derives the unit name from `<mount_target>` using `systemd-escape` and writes a systemd
   mount unit to `/etc/systemd/system/<unit>.mount`. The unit mounts the partition at `<mount_target>` with type
   `<filesystem_type>` and default options.
6. **Enable & start** — reloads the `systemd` daemon, enables the mount unit, and starts it (without restarting
   an already-mounted volume, to avoid disruption).

The mount unit is wanted by `multi-user.target` and uses `DefaultDependencies=yes`, which orders the mount before
the `local-fs.target` (which is itself ordered before the `sysinit.target`): the volume is therefore
automatically mounted at boot — before the `sysinit.target`. If the volume is not currently mounted (for example
because it is new), the entrypoint mounts it during the run.

### Parameters

The entrypoint declares the following inputs:

- `ayasuna__utilities__host__inputs__device_serial` (`str`, required) — the serial number of the (block) device
  which should back the data volume, generally a disk (or drive).
- `ayasuna__utilities__host__inputs__partition_name` (`str`, required) — the name to set for the partition.
- `ayasuna__utilities__host__inputs__filesystem_type` (`str`, required) — the filesystem that the volume should
  use. One of: `ext4`.
- `ayasuna__utilities__host__inputs__mount_target` (`str`, required) — the mount target path. It is created if
  it doesn't exist.

## Entrypoint: `firewall.yml`

Creates or replaces the nftables firewall configuration without applying it.

### Usage

```yaml
---
- name: "Configuring the nftables firewall"
  hosts: "targets"
  gather_facts: false
  become: true
  tasks:
    - name: "Including the 'ayasuna.utilities.host' role (firewall.yml)"
      ansible.builtin.include_role:
        name: "ayasuna.utilities.host"
        tasks_from: "firewall.yml"
      vars:
        ayasuna__utilities__host__inputs__presets:
          - "filter@input.default"
          - "filter@input.ssh"
          - "filter@log"
        ayasuna__utilities__host__inputs__definitions:
          - "chain MY_CHAIN { tcp dport 8080 counter accept; }"
        ayasuna__utilities__host__inputs__prerouting_chains: [ ]
        ayasuna__utilities__host__inputs__input_chains:
          - "MY_CHAIN"
        ayasuna__utilities__host__inputs__forward_chains: [ ]
        ayasuna__utilities__host__inputs__output_chains: [ ]
        ayasuna__utilities__host__inputs__postrouting_chains: [ ]
```

### Behavior

The entrypoint **only** creates or replaces the file `/etc/nftables.conf`; it does **not** apply the
configuration to the running kernel. Applying the configuration is the caller's responsibility (for example via
`nft -f /etc/nftables.conf`); on Debian the `nftables` package ships a `systemd` service that loads
`/etc/nftables.conf` at boot.

The generated file contains a single `table inet AYASUNA_UTILITIES_HOST`, which is replaced wholesale on every
run (any previous rules in the table are discarded). The table is composed of:

- The custom `<definitions>`, inserted at the beginning of the table (before all of the `SYSTEM` chains).
- The `SYSTEM` base chains described below, which jump to the user chains given in the `*_chains` inputs.

The base chains (one per Netfilter hook) are:

| Base chain           | Hook          | Type     | Priority | Default policy |
|----------------------|---------------|----------|----------|----------------|
| `SYSTEM_PREROUTING`  | `prerouting`  | `filter` | `-101`   | `accept`       |
| `SYSTEM_INPUT`       | `input`       | `filter` | `49`     | `drop`         |
| `SYSTEM_FORWARD`     | `forward`     | `filter` | `49`     | `drop`         |
| `SYSTEM_OUTPUT`      | `output`      | `filter` | `49`     | `accept`       |
| `SYSTEM_POSTROUTING` | `postrouting` | `nat`    | `224`    | `accept`       |

The `SYSTEM_INPUT`, `SYSTEM_FORWARD`, and `SYSTEM_OUTPUT` base chains jump, in order, to a `*_BEFORE` chain (containing
the rules of the enabled presets), then to the user chains, then to an `*_AFTER` chain; the
`SYSTEM_PREROUTING` and `SYSTEM_POSTROUTING` base chains jump directly to the user chains. The priorities are
chosen so that the base chains run as late as possible for their hook without conflicting with netfilter-
internal operations. The `postrouting` base chain is a `nat`-type chain (only the first packet of each flow is
processed), so it is not suitable for filtering.

`<presets>` enables predefined rule sets:

- `filter@log` — logs packets that hit the default policy of the filter base chains (rate-limited to 20/minute).
- `filter@forward.default` — accepts forwarded packets that belong to an existing flow, and drops packets that
  belong to invalid flows.
- `filter@input.default` — applies sane default input rules: accepts packets that belong to an existing flow,
  drops invalid packets, accepts valid loopback traffic (and drops invalid loopback traffic), and allows safe
  ICMP/ICMPv6 packets (especially for IPv6, per RFC 4890). This preset should generally be enabled.
- `filter@input.ssh` — accepts all SSH input traffic on port 22.

`<definitions>` may be anything that is valid within a `table inet` block, but must not contain the string
`SYSTEM` (case insensitive) and must not define base chains. The chains listed in the `*_chains` inputs must be
defined in `<definitions>` (the role never defines them itself) and are jumped to in the order given.

### Parameters

The entrypoint declares the following inputs:

- `ayasuna__utilities__host__inputs__presets` (`list[str]`, required) — the rule presets to use when generating
  the firewall. One of: `filter@log`, `filter@forward.default`, `filter@input.default`, `filter@input.ssh`.
- `ayasuna__utilities__host__inputs__definitions` (`list[str]`, required) — the additional definitions to add to
  the firewall. May be anything that is valid within a `table inet` block, but must not contain the string
  `SYSTEM` (case insensitive) and must not define base chains.
- `ayasuna__utilities__host__inputs__prerouting_chains` (`list[str]`, required) — the names of the chains to
  jump to for prerouting (hook `prerouting`, type `filter`); jumped to in the given order.
- `ayasuna__utilities__host__inputs__input_chains` (`list[str]`, required) — the names of the chains to jump to
  for input filtering (hook `input`, type `filter`); jumped to in the given order.
- `ayasuna__utilities__host__inputs__forward_chains` (`list[str]`, required) — the names of the chains to jump
  to for forward filtering (hook `forward`, type `filter`); jumped to in the given order.
- `ayasuna__utilities__host__inputs__output_chains` (`list[str]`, required) — the names of the chains to jump to
  for output filtering (hook `output`, type `filter`); jumped to in the given order.
- `ayasuna__utilities__host__inputs__postrouting_chains` (`list[str]`, required) — the names of the chains to
  jump to for postrouting (hook `postrouting`, type `nat`); jumped to in the given order.

## Entrypoint: `users.yml`

Sets up users.

### Usage

```yaml
---
- name: "Setting up users"
  hosts: "targets"
  gather_facts: false
  become: true
  tasks:
    - name: "Including the 'ayasuna.utilities.host' role (users.yml)"
      ansible.builtin.include_role:
        name: "ayasuna.utilities.host"
        tasks_from: "users.yml"
      vars:
        ayasuna__utilities__host__inputs__users:
          - name: "root"
            password: "root-password"
            public_keys:
              - name: "my-key"
                content: "AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyMaterial..."
                type: "ssh-ed25519"
          - name: "alice"
            password: "alice-password"
            public_keys:
              - name: "alice-key"
                content: "AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyMaterial..."
                type: "ssh-ed25519"
```

### Behavior

For each user in `<users>`, the entrypoint performs the following:

1. **Account** — creates (or updates) the user account (via `ansible.builtin.user`) with login shell
   `/bin/bash` and a home directory; the password is set (as a SHA-512 hash) on every run.
2. **SSH keys** — if the user has one or more public keys, the `~/.ssh/authorized_keys` file is managed **exclusively**
   (via `ansible.posix.authorized_key`): it contains exactly the given keys, one per line in the
   format `<type> <content> <name>` (for example
   `ssh-ed25519 AAAA... my-key`), and any other keys are removed. The `~/.ssh` directory is managed as well.
3. **Sudo** — for every user **except** `root`, the file `/etc/sudoers.d/00-<name>` (mode `0440`, owned by
   `root:root`) is written, granting the user passwordless sudo (`<name> ALL=(ALL:ALL) NOPASSWD:ALL`).

`<users>` must contain at least one user, and the `root` user must be listed exactly once.

### Parameters

The entrypoint declares the following inputs:

- `ayasuna__utilities__host__inputs__users` (`list[dict]`, required) — the users to set up/configure; all of the
  users (except for `root`) will be able to become root by using `sudo`. Must contain at least one user, and the
  `root` user exactly once.
- `ayasuna__utilities__host__inputs__users[*].name` (`str`, required) — the user name.
- `ayasuna__utilities__host__inputs__users[*].password` (`str`, required) — the password of the user.
- `ayasuna__utilities__host__inputs__users[*].public_keys` (`list[dict]`, required) — the public keys to set up.
- `ayasuna__utilities__host__inputs__users[*].public_keys[*].name` (`str`, required) — the name of the public
  key.
- `ayasuna__utilities__host__inputs__users[*].public_keys[*].content` (`str`, required) — the contents of the
  public key.
- `ayasuna__utilities__host__inputs__users[*].public_keys[*].type` (`str`, required) — the public key type.
  One of: `ecdsa-sha2-nistp521`, `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp256`, `ssh-ed25519`, `ssh-rsa`.

## References

- [argument_specs.yml](../../collections/utilities/roles/host/meta/argument_specs.yml) — the argument
  specification of the role, from which the inputs listed in the Parameters sections are derived.
- [RFC 4890 (Neighbor Discovery for IP version 6)](https://datatracker.ietf.org/doc/html/rfc4890) — the
  specification the `filter@input.default` preset uses to decide which ICMPv6 packets are safe to accept.
- [apt (8) (man page)](https://manpages.debian.org/stable/apt/apt.8.en.html) — the APT package manager that
  `packages.yml` uses to update, upgrade, and install packages.
- [hostname (7) (man page)](https://manpages.debian.org/stable/manpages/hostname.7.en.html) — the system hostname
  mechanism that `hostname.yml` configures.
- [hosts (5) (man page)](https://manpages.debian.org/stable/manpages/hosts.5.en.html) — the format of the
  `/etc/hosts` file that `hostname.yml` manages.
- [sshd_config (5) (man page)](https://manpages.debian.org/stable/openssh-server/sshd_config.5.en.html) — the
  format of the `/etc/ssh/sshd_config` file that `ssh.yml` writes.
- [ssh-keygen (1) (man page)](https://manpages.debian.org/stable/openssh-client/ssh-keygen.1.en.html) — the tool
  that `ssh.yml` uses to generate the host keys.
- [parted (8) (man page)](https://manpages.debian.org/stable/parted/parted.8.en.html) — the partitioning tool
  that `volume.yml` uses to create the GPT partition table and the partition.
- [mkfs.ext4 (8) (man page)](https://manpages.debian.org/stable/e2fsprogs/mkfs.ext4.8.en.html) — the tool used
  to create the `ext4` filesystem that `volume.yml` sets up.
- [systemd.mount (5) (man page)](https://manpages.debian.org/stable/systemd/systemd.mount.5.en.html) — the
  format of the `.mount` unit that `volume.yml` writes.
- [systemd.special (7) (man page)](https://manpages.debian.org/stable/systemd/systemd.special.7.en.html) — the
  special units (`multi-user.target`, `local-fs.target`, `sysinit.target`, ...) that determine when the volume is
  mounted at boot.
- [systemd-escape (1) (man page)](https://manpages.debian.org/stable/systemd/systemd-escape.1.en.html) — the
  tool that `volume.yml` uses to derive the mount unit name from the mount target.
- [udevadm (8) (man page)](https://manpages.debian.org/stable/udev/udevadm.8.en.html) — the tool that
  `volume.yml` uses to settle the UDEV event queue.
- [lsblk (8) (man page)](https://manpages.debian.org/stable/util-linux/lsblk.8.en.html) — the tool that
  `volume.yml` uses to identify block devices and their serial numbers.
- [nft (8) (man page)](https://manpages.debian.org/stable/nftables/nft.8.en.html) — the nftables command and
  configuration language used in the firewall configuration that `firewall.yml` writes.
- [sudoers (5) (man page)](https://manpages.debian.org/stable/sudo/sudoers.5.en.html) — the format of the
  sudoers files that `users.yml` writes.
- [authorized_keys (5) (man page)](https://manpages.debian.org/stable/openssh-server/authorized_keys.5.en.html) —
  the format of the `authorized_keys` files that `users.yml` manages.
- [useradd (8) (man page)](https://manpages.debian.org/stable/passwd/useradd.8.en.html) — the user account
  management that `users.yml` configures.
- [ansible.builtin.apt (Ansible documentation)](https://docs.ansible.com/projects/ansible/latest/collections/ansible/builtin/apt_module.html) —
  the module that `packages.yml` uses to update, upgrade, and install packages.
- [ansible.builtin.user (Ansible documentation)](https://docs.ansible.com/projects/ansible/latest/collections/ansible/builtin/user_module.html) —
  the module that `users.yml` uses to create and manage user accounts.
- [ansible.posix.authorized_key (Ansible documentation)](https://docs.ansible.com/projects/ansible/latest/collections/ansible/posix/authorized_key_module.html) —
  the module that `users.yml` uses to manage the `authorized_keys` files.
- [community.general.parted (Ansible documentation)](https://docs.ansible.com/projects/ansible/latest/collections/community/general/parted_module.html) —
  the module that `volume.yml` uses to create the GPT partition.
- [community.general.filesystem (Ansible documentation)](https://docs.ansible.com/projects/ansible/latest/collections/community/general/filesystem_module.html) —
  the module that `volume.yml` uses to create the filesystem.
- [ansible.builtin.systemd_service (Ansible documentation)](https://docs.ansible.com/projects/ansible/latest/collections/ansible/builtin/systemd_service_module.html) —
  the module that `volume.yml` uses to enable and start the mount unit.

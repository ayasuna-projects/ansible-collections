# Ingot

The `ayasuna.utilities.ingot` role builds and deploys **ingots**: golden squashfs images of a Debian system
that (U)EFI-booting hosts can run. An ingot wraps an Ansible role (the *ingot role*) whose entrypoints — the *hooks* —
configure the host. Different hooks are called at different points in time: some run once during the build,
some run on every boot of the host, and some run once during the test phase of the build (see
[Hooks](#hooks) for which hook is called when).

The role has no default entrypoint: each entrypoint must be included explicitly via
`ansible.builtin.include_role` with `tasks_from`. Its entrypoints are:

- `build.yml` — builds an ingot on the host the play runs on and tests it before the build is considered
  successful.
- `deploy.yml` — deploys a previously built ingot to the block device of a host.

All inputs of both entrypoints are declared as variables using the prefix `ayasuna__utilities__ingot__inputs__`.

## How ingots work

Ingots aim to be a middle ground between full-blown golden disk images and systems that are managed manually
(or semi-manually via tools like Ansible). They address the following drawbacks of those approaches:

- **Golden disk images** generally require a dedicated, separate infrastructure that distributes (and/or
  applies) the images to the hosts — normally involving PXE boot and services such as
  [Canonical MAAS](https://canonical.com/maas). Ingots, on the other hand, are not full disk images: they are
  golden squashfs images of a Debian system that can be uploaded to a prepared host while it is still running;
  the host can then be rebooted to boot into the new ingot. Up to a configurable amount of previously uploaded
  ingots stay available, so the host can also boot into an earlier ingot (assuming the newer ingot does not
  mutate the persistent state in a non-backwards-compatible way). The one caveat: the host must be (partially)
  prepared manually for the very first ingot upload — every deployment after the first one can be fully
  autonomous (similar to golden disk images, via the `deploy.yml` entrypoint).
- **Manually managed hosts** (or hosts managed semi-manually via tools like Ansible) easily suffer from
  configuration drift, especially if the host is in use for a long time. Ingots are immutable at their core: all
  modifications to the system configuration made during runtime are by default only made on a `tmpfs` and
  therefore lost with a reboot. Software that is installed on the root filesystem of the host is gone after the next
  reboot, so the system always comes back to the state that was baked into the ingot at build time. Ingots by default
  provide the directory `/var/lib/ingot/data/`, which is persisted across reboots, for state that needs to survive (the
  `ayasuna.ingot.k8s` ingot makes heavy use of it).

Ingots only support (U)EFI boot.

### Boot procedure

The normal boot procedure of an ingot is as follows:

1. The system shows the GRUB bootloader, with the last ingot that was uploaded to the host as the default
   selection.
2. The custom `initramfs` of the ingot is started, which prepares an `overlayfs` (using the ingot, the squashfs
   image, as the read-only lowerdir and a `tmpfs` as the upperdir). The `overlayfs` is mounted at `/`.
3. The `initramfs` hands control over to the ingot's init system (ingots are based on Debian, i.e. `systemd`).
4. The normal `systemd` boot process begins, during which a few special services are called. Each service calls
   a specific entrypoint (hook) of the ingot role the ingot was built with, and the services and their hooks are
   called in this order — each must run to completion before the next is called:
    - `ingot-local.service` — calls the `local.yml` hook.
    - `ingot-network.service` — calls the `network.yml` hook.
    - `ingot-final.service` — calls the `final.yml` hook.

### Directories

When running an ingot, a few special directories exist:

- `/var/lib/ingot/boot/` — the directory into which the ESP partition (to which the GRUB bootloader is
  installed) is mounted. This directory is part of the internal "API": users and ingots should refrain from
  modifying it or its contents (the "BOOT" partition).
- `/var/lib/ingot/deployment/` — the directory in which the ingots (and their configuration) that have been
  uploaded to the host can be found. This directory is part of the internal "API": users and ingots should
  refrain from modifying it or its contents (the "DEPLOYMENT" partition).
- `/var/lib/ingot/data/` — the built-in directory in which users and ingots may store files they want to
  persist across reboots (the "DATA" partition).

## Entrypoint: `build.yml`

Builds a new ingot via Packer and QEMU.

An ingot is a squashfs image of a Debian filesystem that follows some additional contracts: it contains, for
example, well-defined systemd services that are executed during every boot to configure the host (see
[Hooks](#hooks)).

### Usage

The entrypoint performs the build on the host the play runs on (the example below assumes this is the local
machine) and expects to be run as `root`. Its inputs are declared as variables using the prefix
`ayasuna__utilities__ingot__inputs__`:

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
    ayasuna__utilities__ingot__inputs__build_operating_system: "debian:13-amd64"
    # The root password set during the OS installation; it may differ from the password the ingot configures during its boot process
    ayasuna__utilities__ingot__inputs__build_users_root_password: "some-root-pw"
    # The Ansible collections to install into the ingot; must include the collection containing the ingot role (here: this repository)
    ayasuna__utilities__ingot__inputs__build_ansible_collections:
      - name: "git@github.com:ayasuna-projects/ansible-collections.git#/collections/"
        type: "git"
        version: "main"
    # The directory in which the build process puts its temporary files
    ayasuna__utilities__ingot__inputs__working_directory: "/tmp/build_rescue_ingot/"
    ayasuna__utilities__ingot__inputs__qemu_accelerator: "kvm"
    # If true, QEMU runs in headless mode (no GUI)
    ayasuna__utilities__ingot__inputs__qemu_headless: false
    # These OVMF firmware files are provided by the 'ovmf' package and must be present on the build host
    ayasuna__utilities__ingot__inputs__qemu_efi_code: "/usr/share/OVMF/OVMF_CODE_4M.fd"
    ayasuna__utilities__ingot__inputs__qemu_efi_vars: "/usr/share/OVMF/OVMF_VARS_4M.fd"
    # The location of the resulting ingot (squashfs image); a local path here because the ingot is built locally
    ayasuna__utilities__ingot__inputs__target_file: "{{ playbook_dir }}/../artifacts/rescue.amd64.squashfs"
    ayasuna__utilities__ingot__inputs__build_ansible_role_fqn: "ayasuna.ingot.rescue"
    # This example embeds the hostname to configure and the users allowed to connect to the ingot during the build process.
    # They may be omitted and instead provided at deployment time via 'ayasuna__utilities__ingot__inputs__source_arguments'
    # (or for the test environment via 'ayasuna__utilities__ingot__inputs__test_arguments'),
    # or kept and overwritten (in whole or in part) via those variables at deployment time.
    ayasuna__utilities__ingot__inputs__build_ansible_role_arguments:
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
              type: "<your_key_type>"

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
    # No test arguments are needed here because all arguments were embedded during the build process
    # (normally you would instead specify the role arguments to use for the test here)
    ayasuna__utilities__ingot__inputs__test_arguments: { }
  tasks:
    - ansible.builtin.import_role:
        name: "ayasuna.utilities.ingot"
        tasks_from: "build.yml"
```

In this example the role builds a rescue ingot using the `ayasuna.ingot.rescue` role as the ingot role: the
hostname `rescue01` and the users to set up are embedded into the ingot during the build, and the resulting
ingot is written to `{{ playbook_dir }}/../artifacts/rescue.amd64.squashfs`.

### Prerequisites

- The host that runs the build must provide the following packages: `ovmf`, `qemu-system`, `squashfs-tools`,
  `parted`, `grub-efi-amd64`, `e2fsprogs`, `dosfstools`.
- [HashiCorp Packer](https://developer.hashicorp.com/packer/install#linux) must be installed on that host.
- All tasks of the entrypoint expect to be run as `root`.

### Behavior

The entrypoint uses [HashiCorp Packer](https://developer.hashicorp.com/packer/docs) (with the QEMU builder) to
start virtual machines in which the ingot is built and tested:

1. **Build** — a build VM is started in which Debian is installed (unattended, via preseed). After the OS
   installation, an Ansible playbook is run inside the VM to customize and finalize the installation (for
   example installing the systemd services that call the hooks during boot, and configuring default kernel
   parameters); the playbook also calls the `install.yml` hook of the ingot role given in
   `<build_ansible_role_fqn>`. The VM is then shut down and the squashfs image (the actual ingot) is created
   from the root filesystem of the VM image.
2. **Test** — the created ingot is tested in a second VM: the `deploy.yml` entrypoint of this role deploys the
   ingot to the disk of the test VM, the VM boots into it, and an Ansible playbook is executed inside it that,
   next to a set of base tests, calls the `test.yml` hook of the ingot role (to perform ingot-specific tests).
   The ingot is only considered successfully built if all boot hooks and this hook complete successfully.
3. **Artifact** — after the successful test, the ingot is copied to `<target_file>`.

### Hooks

The ingot role given in `<build_ansible_role_fqn>` defines how the ingot configures the host. It is called via
the following entrypoints (hooks), and the role must implement *all* of them:

- `install.yml` — called exactly once during the build, after the OS and the systemd services (that call the
  other hooks during boot) have been installed. No deployment arguments are available at this stage. It is
  intended to be used to install/download software and set up environment-agnostic configuration.
- `local.yml` — called during every boot after the root filesystem has been mounted, but before any network
  configuration has been applied to the system. Everything that can be set up without an existing network
  configuration (e.g. the firewall and the network configuration itself) should be set up here.
- `network.yml` — called during every boot after the network manager has started and the `local.yml` hook has
  completed. Note that while the network manager has started at this point, the state of the network is not yet
  fully defined.
- `final.yml` — called at the end of every boot, after the `network.yml` hook has completed. At this point the
  system is considered fully booted.
- `test.yml` — called exactly once within the test VM (see [Behavior](#behavior)), after the `final.yml` hook
  has completed, to test the built ingot.

The hooks should, wherever possible, use systemd to configure the system: if the deployment arguments indicate
that a specific service should be running, that service should be integrated (possibly transiently) with systemd
by creating a `*.service` file.

The root filesystem (`/`) is mounted as an `overlayfs` that uses a `tmpfs` for the upper filesystem, so all
changes that the boot hooks apply to the root filesystem are temporary. To persist data across reboots, the
ingot role must either mount a separate drive itself or use the `/var/lib/ingot/data/` directory (see
[Directories](#directories)).

### Parameters

The entrypoint declares the following inputs (all using the prefix `ayasuna__utilities__ingot__inputs__`):

- `ayasuna__utilities__ingot__inputs__build_operating_system` (`str`, required) — the operating system to
  install. One of: `debian:13-amd64`.
- `ayasuna__utilities__ingot__inputs__build_users_root_password` (`str`, required) — the password to set for
  the `root` user during the OS installation.
- `ayasuna__utilities__ingot__inputs__build_ansible_collections` (`list[dict]`, required) — the Ansible
  collections to install and copy into the ingot. They are installed on the build host by calling
  `ansible-galaxy collection install` with a requirements file; this parameter provides a subset of the options
  outlined in
  the [Ansible documentation](https://docs.ansible.com/projects/ansible/latest/collections_guide/collections_installing.html#install-multiple-collections-with-a-requirements-file).
- `ayasuna__utilities__ingot__inputs__build_ansible_collections[*].type` (`str`, required) — determines what
  `name` represents and how to interpret it. One of: `file`, `galaxy`, `git`, `url`, `dir`, `subdirs`.
- `ayasuna__utilities__ingot__inputs__build_ansible_collections[*].name` (`str`, required) — the name of the
  collection (s) to install. The format and meaning depends on `<type>` (e.g. it might be a URL or a path).
- `ayasuna__utilities__ingot__inputs__build_ansible_collections[*].version` (`str`, optional) — the version of
  the collection (s) to install.
- `ayasuna__utilities__ingot__inputs__build_ansible_role_fqn` (`str`, required) — the fully qualified name of
  the role whose entrypoints (the hooks) are called during the build and on every boot of the ingot. See
  [Hooks](#hooks).
- `ayasuna__utilities__ingot__inputs__build_ansible_role_arguments` (`dict[str, any]`, optional, default `{}`)
  — the static arguments/variables to "call" all hooks of the role with. If an argument is also set via the
  deployment arguments, the deployment argument takes precedence; overwriting arguments this way is generally
  not recommended, as the deployment arguments are not available during the build process.
- `ayasuna__utilities__ingot__inputs__test_arguments` (`dict[str, any]`, required) — the arguments to "call"
  the ingot's hooks (e.g. `local.yml`, `network.yml`, `final.yml`) with when testing the ingot in the test VM.
- `ayasuna__utilities__ingot__inputs__test_ssh_ip` (`str`, required) — the IP address the test VM is connected
  to (via SSH).
- `ayasuna__utilities__ingot__inputs__test_ssh_port` (`int`, required) — the port the test VM is connected to.
- `ayasuna__utilities__ingot__inputs__test_ssh_username` (`str`, required) — the username to use for the
  connection to the test VM.
- `ayasuna__utilities__ingot__inputs__test_ssh_private_key` (`str`, required) — the private key to use for the
  connection to the test VM.
- `ayasuna__utilities__ingot__inputs__test_interfaces` (`list[dict]`, required) — the network interfaces to
  add to the test VM.
- `ayasuna__utilities__ingot__inputs__test_interfaces[*].ipv4_cidr` (`str`, optional, default `null`) — the
  IPv4 CIDR to set up for the interface; the prefix length must be `/24`. The test VM can obtain an address in
  this network via DHCP, in which case it gets the address ending in `.15` of the network (e.g. `10.111.0.15`
  for `10.111.0.0/24`); for a static assignment, addresses above `.100` of the network should be used to avoid
  conflicting with the DHCP server. Set to `null` if no IPv4 network should be set up for the interface (the VM
  can then not communicate with external (IPv4) services via this interface).
- `ayasuna__utilities__ingot__inputs__test_interfaces[*].ipv6_cidr` (`str`, optional, default `null`) — the
  IPv6 CIDR to set up for the interface; the prefix length must be `/64`. The test VM can generate an address in
  this network via SLAAC or set one statically (addresses up to `prefix::1000` are reserved). Set to `null` if
  no IPv6 network should be set up for the interface (the VM can then not communicate with external (IPv6)
  services via this interface).
- `ayasuna__utilities__ingot__inputs__test_interfaces[*].mac` (`str`, required) — the MAC address of the
  interface to add to the test VM.
- `ayasuna__utilities__ingot__inputs__test_disks_root_serial` (`str`, optional, default `TD0000001`) — the
  serial number the root disk of the test VM should have.
- `ayasuna__utilities__ingot__inputs__test_disks_additional` (`list[dict]`, required) — the additional disks to
  add to the test VM.
- `ayasuna__utilities__ingot__inputs__test_disks_additional[*].size` (`int`, required) — the size of the disk
  in MB.
- `ayasuna__utilities__ingot__inputs__test_disks_additional[*].serial` (`str`, required) — the serial number
  the disk should have.
- `ayasuna__utilities__ingot__inputs__qemu_accelerator` (`str`, optional, default `kvm`) — the QEMU
  accelerator to use. One of: `kvm`, `tcg`.
- `ayasuna__utilities__ingot__inputs__qemu_headless` (`bool`, optional, default `true`) — whether to run QEMU
  in headless mode (no GUI).
- `ayasuna__utilities__ingot__inputs__qemu_efi_code` (`str`, optional, default
  `/usr/share/OVMF/OVMF_CODE_4M.fd`) — the path to the UEFI firmware code/implementation. The file is copied to
  a temporary directory before it is used.
- `ayasuna__utilities__ingot__inputs__qemu_efi_vars` (`str`, optional, default
  `/usr/share/OVMF/OVMF_VARS_4M.fd`) — the path to the UEFI firmware variables file (the file in which the
  mutable UEFI variables are stored). The file is copied to a temporary directory before it is used.
- `ayasuna__utilities__ingot__inputs__working_directory` (`str`, required) — the working directory in which the
  build process creates its temporary files. It must end with a `/` and match the regular expression
  `^[a-zA-Z0-9_\-/]+$`. The build process expects exclusive access to the directory, which may be reused for
  consecutive builds (with the same configuration).
- `ayasuna__utilities__ingot__inputs__target_file` (`str`, required) — the path to which the created ingot is
  copied after a successful test. The containing directory must already exist.

## Entrypoint: `deploy.yml`

Deploys a previously built ingot (built via the `build.yml` entrypoint) to the block device of a host.

### Usage

The entrypoint runs on the host the ingot should be deployed to, and Ansible must be able to connect to that
host via SSH either as `root` or with `ansible_become: true` (the individual tasks of the entrypoint do not use
the `become` directive). Its inputs are declared as variables using the prefix
`ayasuna__utilities__ingot__inputs__`:

```yaml
# Deploys the rescue ingot to a host
# The host has to be prepared for the initial deployment first; subsequent deployments work without issue
- name: "Deploy rescue ingot"
  hosts:
    # the target host must be part of your inventory
    - "rescue01"
  serial: 1
  gather_facts: false
  vars:
    # The following three variables are normally specified in inventory files, but are included here for brevity
    ansible_host: "<target_host_ip>"
    ansible_user: "<your_username>"
    # 'ansible_become: true' is required for the rescue ingot, as it does not allow SSH access via root
    ansible_become: true
    # The previously built ingot (from the "Build rescue ingot" playbook above)
    ayasuna__utilities__ingot__inputs__source_ingot: "{{ playbook_dir }}/../artifacts/rescue.amd64.squashfs"
    # No arguments are needed here because all arguments were embedded during the build process
    # (normally you would instead specify the role arguments to use here)
    ayasuna__utilities__ingot__inputs__source_arguments: { }
    # The device to deploy the ingot to; three partitions ("BOOT", "DEPLOYMENT", "DATA") are created on it
    ayasuna__utilities__ingot__inputs__target_device_path: "/dev/sda"
    # Size of the "BOOT" partition in MiB
    ayasuna__utilities__ingot__inputs__target_partitions_boot_size: 512
    # The size in MiB of the "DEPLOYMENT" partition; the "DATA" partition uses the remaining space
    ayasuna__utilities__ingot__inputs__target_partitions_deployment_size: 6144
    # How many ingot deployments to keep (including the current one), at least one;
    # the "DEPLOYMENT" partition must be large enough to hold this many ingots
    ayasuna__utilities__ingot__inputs__target_partitions_deployment_history: 3
  tasks:
    - ansible.builtin.import_role:
        name: "ayasuna.utilities.ingot"
        tasks_from: "deploy.yml"

    - name: "[Deploy rescue ingot] Rebooting host"
      ansible.builtin.reboot:
        reboot_timeout: 300
```

In this example the role deploys the rescue ingot (built by the `Build rescue ingot` playbook above) to
`/dev/sda` of the host `rescue01`, keeps the last three deployments, and reboots the host so that it boots into
the new ingot.

### Preparing a host for the initial deployment

The entrypoint requires Ansible to be able to connect to the host via SSH. This is generally not a problem for
hosts that already run an ingot (assuming the ingot allows SSH access and configures/sets up the user Ansible
uses (`<ansible_user>`) to connect to it accordingly).

If the host is not yet running an ingot, a few manual steps are required to prepare it for the entrypoint:

1. The following packages must be installed on the host: `sudo`, `openssh-server`, `grub-efi-amd64`, `parted`,
   `e2fsprogs`, `dosfstools`.
2. `<ansible_user>` must be able to connect to the host via SSH (i.e. Ansible must be able to connect to the
   host) and must be able to become `root` — either by connecting directly as `root` or by using the connection
   variable `ansible_become: true` (the individual tasks of the entrypoint do not use the `become` directive).
3. The block device to deploy to (`<target_device_serial>` or `<target_device_path>`) must exist and should not
   contain any partition table.

The following example script prepares a host for the initial ingot deployment. It must be run as `root` and
sets up a non-root `<ansible_user>` (the user Ansible connects to the host as) with passwordless `sudo`, so
that the deployment can use `ansible_become: true` (with the `sudo` become method) to escalate from
`<ansible_user>` to `root`:

```bash
#!/bin/bash

set -euo pipefail

# The user Ansible connects to the host with
ANSIBLE_USER="ansible"

# That user's SSH public key
ANSIBLE_USER_PUBLIC_KEY="ssh-ed25519 AAAA... user@example.com"

# The interface the address below is added to
HOST_INTERFACE="eth0"

# The CIDR address (IPv4 or IPv6, e.g. 10.10.10.10/24 or fde9:a912:7c84::1000/64) assigned to $HOST_INTERFACE.
# Use the address the host is expected to have once it boots into the ingot (the "ansible_host" value for this host);
# remove the 'ip addr add' command below if the host already has that address in the live environment.
HOST_INTERFACE_ADDRESS="10.10.10.10/24"

# This script must be run as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root" >&2
    exit 1
fi

# Install the packages required for the initial deployment
apt-get update
apt-get install -y sudo openssh-server grub-efi-amd64 parted e2fsprogs dosfstools

# Create the user account with a home directory
useradd -m "$ANSIBLE_USER"

# Set up the user's .ssh directory and authorized_keys file with correct ownership and permissions
mkdir -p "/home/$ANSIBLE_USER/.ssh"
chmod 700 "/home/$ANSIBLE_USER/.ssh"
chown "$ANSIBLE_USER:$ANSIBLE_USER" "/home/$ANSIBLE_USER/.ssh"
echo "$ANSIBLE_USER_PUBLIC_KEY" > "/home/$ANSIBLE_USER/.ssh/authorized_keys"
chmod 600 "/home/$ANSIBLE_USER/.ssh/authorized_keys"
chown "$ANSIBLE_USER:$ANSIBLE_USER" "/home/$ANSIBLE_USER/.ssh/authorized_keys"

# Grant the user passwordless sudo
echo "$ANSIBLE_USER ALL=(ALL:ALL) NOPASSWD:ALL" > "/etc/sudoers.d/00-$ANSIBLE_USER"
chmod 0440 "/etc/sudoers.d/00-$ANSIBLE_USER"
chown root:root "/etc/sudoers.d/00-$ANSIBLE_USER"
visudo -c

# Turn on public key authentication in the sshd_config file
if grep -qE '^[#]*[[:space:]]*PubkeyAuthentication' /etc/ssh/sshd_config; then
    sed -ri 's/^[#]*[[:space:]]*PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
else
    echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config
fi

# Add the address to the interface
ip addr add "$HOST_INTERFACE_ADDRESS" dev "$HOST_INTERFACE"

# Restart SSH
systemctl restart ssh.service
```

> **TIP:** If you are unable to transfer the script to the live environment (e.g. because you are connected via
> VNC), you can gain temporary SSH access to run it as follows:
>
> 1. Switch to the root user (e.g. `sudo su` in a Debian live environment).
> 2. Set a strong password for the `root` user.
> 3. Install `openssh-server` and an editor of your choice (e.g. `apt-get install openssh-server nano`).
> 4. Edit `/etc/ssh/sshd_config` to enable password login (`PasswordAuthentication yes`) and permit root login
>    (`PermitRootLogin yes`).
> 5. Restart the SSH service (`systemctl restart ssh.service`).
> 6. Connect to the host via SSH using `root`.
> 7. Copy the above script (with the correct variable values) into a temporary file and make it executable.
> 8. Run the script.

### SSH

Ingots by default allow non-root users to connect via SSH using public-key authentication (SSH access via
`root` is not allowed by default). Custom ingots are, nevertheless, encouraged to configure the SSH service
themselves, because:

- The host keys the SSH service uses by default are generated during the ingot build process, so if the same
  ingot is deployed to multiple hosts, they all use the same host keys — most likely not what you want.
- The host keys change every time a different ingot (e.g. a newly deployed version of the ingot) is booted on
  the host, which most likely results in your SSH client refusing to connect until the old keys are removed from
  the `known_hosts` file.

One way to configure the SSH service is to use the `ssh.yml` entrypoint of the `ayasuna.utilities.host` role
during the `local.yml` hook (as the `ayasuna.ingot.k8s` ingot does): it allows configuring the directory the SSH
service should use for its host keys (missing host keys are generated as necessary) — for example
`/var/lib/ingot/data/ssh/`, which persists across reboots.

### Behavior

The entrypoint performs the following on the host, in order:

1. **Identify the device** — the target block device is identified by `<target_device_serial>` or
   `<target_device_path>` (exactly one of the two must be specified).
2. **Partition & format** (only if the target device does not yet carry any partitions) — a GPT partition table
   with three partitions is created:
    - `BOOT` — FAT32 with the ESP flag, `<target_partitions_boot_size>` MiB.
    - `DEPLOYMENT` — ext4, `<target_partitions_deployment_size>` MiB.
    - `DATA` — ext4, using the remaining space of the device.

   The size parameters only have an effect if the target device does not yet have any partitions; existing
   partitions (and their filesystems) are left untouched.
3. **Deploy** — the ingot given in `<source_ingot>` is copied to a new deployment directory on the `DEPLOYMENT`
   partition, together with the deployment arguments (`<source_arguments>`). The GRUB bootloader is installed (or
   updated) on the `BOOT` partition such that the most recently deployed ingot becomes the default boot
   entry, while up to `<target_partitions_deployment_history>` previously deployed ingots (including the one
   currently being deployed) remain available for booting. Deployments beyond that number are removed from the
   `DEPLOYMENT` partition.
4. **Reboot** — the host must be rebooted for the new ingot to take effect (see the example playbook above).

The `DEPLOYMENT` partition must be large enough to accommodate `<target_partitions_deployment_history>` ingots.

### Parameters

The entrypoint declares the following inputs (all using the prefix `ayasuna__utilities__ingot__inputs__`):

- `ayasuna__utilities__ingot__inputs__source_ingot` (`str`, required) — the path to the ingot (squashfs image)
  to deploy.
- `ayasuna__utilities__ingot__inputs__source_arguments` (`dict[str, any]`, required) — the arguments to "call"
  the ingot's hooks (e.g. `local.yml`, `network.yml`, `final.yml`) with when the ingot is booted.
- `ayasuna__utilities__ingot__inputs__target_device_serial` (`str`, optional, default `null`) — the serial
  number of the block device to deploy to. Mutually exclusive with `<target_device_path>`: exactly one of the
  two must be specified.
- `ayasuna__utilities__ingot__inputs__target_device_path` (`str`, optional, default `null`) — the path of the
  block device to deploy to. Mutually exclusive with `<target_device_serial>`: exactly one of the two must be
  specified.
- `ayasuna__utilities__ingot__inputs__target_partitions_boot_size` (`int`, optional, default `512`) — the size
  of the `BOOT` partition in MiB. Only has an effect if the partition does not exist yet.
- `ayasuna__utilities__ingot__inputs__target_partitions_deployment_size` (`int`, optional, default `24576`) —
  the size of the `DEPLOYMENT` partition in MiB. Only has an effect if the partition does not exist yet.
- `ayasuna__utilities__ingot__inputs__target_partitions_deployment_history` (`int`, optional, default `10`) —
  the number of ingot deployments to keep, including the one currently being deployed (at least one). The
  `DEPLOYMENT` partition must be large enough to accommodate this many ingots.

## References

- [argument_specs.yml](../../collections/utilities/roles/ingot/meta/argument_specs.yml) — the argument
  specification of the role, from which the inputs listed in the Parameters sections are derived.
- [argument_specs.yml of the `ayasuna.ingot.rescue` role](../../collections/ingot/roles/rescue/meta/argument_specs.yml)
  — the argument specification of the `ayasuna.ingot.rescue` reference role used in the example playbooks.
- [argument_specs.yml of the `ayasuna.ingot.k8s` role](../../collections/ingot/roles/k8s/meta/argument_specs.yml)
  — the argument specification of the `ayasuna.ingot.k8s` reference role.
- [HashiCorp Packer installation](https://developer.hashicorp.com/packer/install#linux) — how to install Packer
  on Linux, which the `build.yml` entrypoint requires.
- [HashiCorp Packer documentation](https://developer.hashicorp.com/packer/docs) — the documentation of Packer,
  the tool the `build.yml` entrypoint uses to build and test ingots.
- [Canonical MAAS](https://canonical.com/maas) — an example of the kind of dedicated infrastructure (PXE boot
  and image distribution) that full-blown golden disk images generally require.
- [Installing collections (Ansible documentation)](https://docs.ansible.com/projects/ansible/latest/collections_guide/collections_installing.html#install-multiple-collections-with-a-requirements-file)
  — the requirements-file options that `<build_ansible_collections>` is a subset of.
- [Privilege escalation (Ansible documentation)](https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_privilege_escalation.html)
  — information about `ansible_become` and privilege escalation with Ansible in general.

# K8s

The `ayasuna.ingot.k8s` role is an [ingot](../utilities/INGOT.md) role for running a node of a
[K3s](https://docs.k3s.io/) cluster (a lightweight Kubernetes distribution) — either a server or an agent —
as an ingot. A booted K8s ingot is a Debian system. On every boot, it configures a hostname and a set of users (each
non-root user with passwordless `sudo`), sets up SSH access via public-key authentication, a bonded (active-backup) WAN
interface with static (and/or DHCPv4) addressing, a locked-down firewall for K3s traffic,
and a unique iSCSI initiator name, and starts a K3s node that uses Flannel for its pod network.

All K3s state — including, for server nodes, the cluster's datastore — and the SSH host keys are stored in
the persistent `/var/lib/ingot/data/` directory (see [Persistence](#persistence)) and survive reboots as well
as redeployments of the ingot to the same host.

## Usage

The role is an ingot role: it is not included directly in a playbook. Instead, it is built into an ingot via
the [`build.yml` entrypoint of the `ayasuna.utilities.ingot` role](../utilities/INGOT.md#entrypoint-buildyml),
and the resulting ingot is deployed to the block device of a (U)EFI-booting host via the `deploy.yml`
entrypoint of the same role.

The overall workflow is as follows:

1. **Build** — build the ingot, with `ayasuna.ingot.k8s` as the ingot role, specifying the K3s version (and,
   optionally, additional packages) to install (see below).
2. **Deploy** — deploy the ingot to a host, passing the node's inputs (the hostname, the users, the WAN
   interface, and the K3s cluster settings) as deployment arguments.
3. **Boot** — the host boots into the ingot; on every boot, the K3s node is (re)configured and started.

A single ingot can be deployed to multiple hosts to form a cluster: each host is deployed with the same ingot
but with different deployment arguments — a unique `<k3s_node_name>` and `<k3s_node_ipv6_ip>` /
`<k3s_node_ipv4_ip>`, and — on every node, including the bootstrap node — `<k3s_cluster_bootstrap_node_ip>`
set to the bootstrap node's IP (the bootstrap node's own IP, in the case of the bootstrap node itself) (see
[Cluster bootstrap](#cluster-bootstrap)).

The role's inputs can be provided at build time (embedded into the ingot) or at deployment time (stored with
each deployment); if an input is given both at build time and at deployment time, the deployment value takes
precedence. One exception: the inputs of the `install.yml` hook — `<k3s_version>` and, optionally,
`<packages>` — only have an effect when the `install.yml` hook (which downloads the K3s binary) runs, i.e.
during the build (it is also the only hook that declares them). They therefore must be provided at build time via
`ayasuna__utilities__ingot__inputs__build_ansible_role_arguments`; providing them at deployment time has no
effect. All other inputs are typically provided at deployment time.

### Build

The example below builds the K8s ingot on the local machine via the `build.yml` entrypoint of the
`ayasuna.utilities.ingot` role. The entrypoint's prerequisites (e.g. the packages the build host must provide)
and its inputs are documented [there](../utilities/INGOT.md#entrypoint-buildyml):

```yaml
# Builds the k8s ingot
- name: "Build k8s ingot"
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
    ayasuna__utilities__ingot__inputs__build_ansible_role_fqn: "ayasuna.ingot.k8s"
    # The inputs for the install hook, which runs during the build (no deployment arguments are available then):
    # the K3s version to install and (optionally) additional APT packages to install
    ayasuna__utilities__ingot__inputs__build_ansible_role_arguments:
      ayasuna__ingot__k8s__inputs__k3s_version: "v1.32.5+k3s1"
      ayasuna__ingot__k8s__inputs__packages: [ ]
    # The directory in which the build process puts its temporary files
    ayasuna__utilities__ingot__inputs__working_directory: "/tmp/build_k8s_ingot/"
    ayasuna__utilities__ingot__inputs__qemu_accelerator: "kvm"
    # If true, QEMU runs in headless mode (no GUI)
    ayasuna__utilities__ingot__inputs__qemu_headless: false
    # These OVMF firmware files are provided by the 'ovmf' package and must be present on the build host
    ayasuna__utilities__ingot__inputs__qemu_efi_code: "/usr/share/OVMF/OVMF_CODE_4M.fd"
    ayasuna__utilities__ingot__inputs__qemu_efi_vars: "/usr/share/OVMF/OVMF_VARS_4M.fd"
    # The location of the resulting ingot; a local path here because the ingot is built locally
    ayasuna__utilities__ingot__inputs__target_file: "{{ playbook_dir }}/../artifacts/k8s.amd64.squashfs"
    # The inputs the ingot's hooks are called with when the ingot is tested in the test VM
    ayasuna__utilities__ingot__inputs__test_arguments:
      # The hostname the ingot configures at boot during the test
      ayasuna__ingot__k8s__inputs__name: "k8s01"
      # The users the ingot sets up at boot during the test; each non-root user can use passwordless 'sudo'
      ayasuna__ingot__k8s__inputs__users:
        - name: "root" # required for the k8s ingot
          password: "<root_password>"
          # Public keys for the root user have no effect for the k8s ingot, as it does not allow SSH access via root
          public_keys: [ ]
        - name: "<your_username>"
          password: "<your_password>"
          public_keys:
            - name: "<your_key_name>"
              content: "<your_public_key>"
              type: "ssh-ed25519"
      # The (single) physical interface of the test VM that forms the WAN bond
      ayasuna__ingot__k8s__inputs__wan_interfaces:
        - mac: "1e:0e:d6:f7:29:b2"
      # A static address for the WAN interface; addresses above .100 of the test network avoid conflicts with the DHCP server
      ayasuna__ingot__k8s__inputs__wan_ips:
        - "10.111.0.200/24"
      ayasuna__ingot__k8s__inputs__wan_nameservers:
        - "1.1.1.1"
      ayasuna__ingot__k8s__inputs__wan_dhcp: false
      ayasuna__ingot__k8s__inputs__wan_accept_ra: false
      # The default route via the gateway of the test network
      ayasuna__ingot__k8s__inputs__wan_routes:
        - to: "0.0.0.0/0"
          via: "10.111.0.1"
      # The K3s node: a server that bootstraps the cluster
      ayasuna__ingot__k8s__inputs__k3s_node_type: "server"
      ayasuna__ingot__k8s__inputs__k3s_node_name: "k8s01"
      ayasuna__ingot__k8s__inputs__k3s_node_ipv4_ip: "10.111.0.200"
      ayasuna__ingot__k8s__inputs__k3s_cluster_domain: "cluster.local"
      ayasuna__ingot__k8s__inputs__k3s_cluster_ipv4_service_network: "10.43.0.0/16"
      ayasuna__ingot__k8s__inputs__k3s_cluster_ipv4_pod_network: "10.42.0.0/16"
      # The networks from which input traffic to the node is accepted; must include the network(s) of the K8s nodes
      ayasuna__ingot__k8s__inputs__k3s_cluster_ipv4_trusted_networks:
        - "10.111.0.0/24"
      ayasuna__ingot__k8s__inputs__k3s_cluster_flannel_backend: "vxlan"
      ayasuna__ingot__k8s__inputs__k3s_cluster_token: "<k3s_cluster_token>"
      # The node's own IP: this node is the bootstrap node of the cluster
      ayasuna__ingot__k8s__inputs__k3s_cluster_bootstrap_node_ip: "10.111.0.200"
    # The ingot uses a static address (no DHCP), so the test VM is connected to at its static address
    ayasuna__utilities__ingot__inputs__test_ssh_ip: "10.111.0.200"
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

In this example the ingot is built with the K3s version `v1.32.5+k3s1` embedded, and — without any other
embedded inputs — the resulting ingot is written to `{{ playbook_dir }}/../artifacts/k8s.amd64.squashfs`.
During the build, the ingot is tested in the test VM with the arguments given in
`ayasuna__utilities__ingot__inputs__test_arguments`: the test node is a K3s server that bootstraps a single-
node cluster.

### Deploy

The example below deploys the K8s ingot to the host `k8s01`, via the `deploy.yml` entrypoint of the
`ayasuna.utilities.ingot` role. The entrypoint's prerequisites and inputs are documented
[there](../utilities/INGOT.md#entrypoint-deployyml):

```yaml
# Deploys the k8s ingot to a host
# The host has to be prepared for the initial deployment first; subsequent deployments work without issue
- name: "Deploy k8s ingot"
  hosts:
    # the target host must be part of your inventory
    - "k8s01"
  serial: 1
  gather_facts: false
  vars:
    # The following three variables are normally specified in inventory files, but are included here for brevity
    ansible_host: "<target_host_ip>"
    ansible_user: "<your_username>"
    # 'ansible_become: true' is required for the k8s ingot, as it does not allow SSH access via root
    ansible_become: true
    # The previously built ingot (from the "Build k8s ingot" playbook above)
    ayasuna__utilities__ingot__inputs__source_ingot: "{{ playbook_dir }}/../artifacts/k8s.amd64.squashfs"
    # The inputs the ingot's hooks are called with when the host boots into the ingot
    ayasuna__utilities__ingot__inputs__source_arguments:
      # The hostname the ingot configures at boot
      ayasuna__ingot__k8s__inputs__name: "k8s01"
      # The users the ingot sets up at boot; each non-root user can use passwordless 'sudo'
      ayasuna__ingot__k8s__inputs__users:
        - name: "root" # required for the k8s ingot
          password: "<root_password>"
          # Public keys for the root user have no effect for the k8s ingot, as it does not allow SSH access via root
          public_keys: [ ]
        - name: "<your_username>"
          password: "<your_password>"
          public_keys:
            - name: "<your_key_name>"
              content: "<your_public_key>"
              type: "ssh-ed25519"
      # The (physical) interfaces of the host that form the WAN bond
      ayasuna__ingot__k8s__inputs__wan_interfaces:
        - mac: "<mac_address_of_physical_interface_1>"
        - mac: "<mac_address_of_physical_interface_2>"
      # The (static) addresses of the WAN interface
      ayasuna__ingot__k8s__inputs__wan_ips:
        - "<ipv4_cidr_of_the_node>"
      ayasuna__ingot__k8s__inputs__wan_nameservers:
        - "<nameserver_1>"
        - "<nameserver_2>"
      ayasuna__ingot__k8s__inputs__wan_dhcp: false
      ayasuna__ingot__k8s__inputs__wan_accept_ra: false
      # The default route via the gateway of the host's network
      ayasuna__ingot__k8s__inputs__wan_routes:
        - to: "0.0.0.0/0"
          via: "<gateway>"
      # The K3s node: the server that bootstraps the cluster
      ayasuna__ingot__k8s__inputs__k3s_node_type: "server"
      ayasuna__ingot__k8s__inputs__k3s_node_name: "k8s01"
      ayasuna__ingot__k8s__inputs__k3s_node_ipv4_ip: "<ipv4_ip_of_the_node>"
      ayasuna__ingot__k8s__inputs__k3s_cluster_domain: "cluster.local"
      ayasuna__ingot__k8s__inputs__k3s_cluster_ipv4_service_network: "10.43.0.0/16"
      ayasuna__ingot__k8s__inputs__k3s_cluster_ipv4_pod_network: "10.42.0.0/16"
      # The networks from which input traffic to the node is accepted; must include the network(s) of the K8s nodes
      ayasuna__ingot__k8s__inputs__k3s_cluster_ipv4_trusted_networks:
        - "<network_of_the_k8s_nodes>"
      ayasuna__ingot__k8s__inputs__k3s_cluster_flannel_backend: "vxlan"
      ayasuna__ingot__k8s__inputs__k3s_cluster_token: "<k3s_cluster_token>"
      # The node's own IP: this node is the bootstrap node of the cluster
      ayasuna__ingot__k8s__inputs__k3s_cluster_bootstrap_node_ip: "<ipv4_ip_of_the_node>"
    # The device to deploy the ingot to; three partitions ("BOOT", "DEPLOYMENT", "DATA") are created on it
    ayasuna__utilities__ingot__inputs__target_device_path: "/dev/sda"
    # Size of the "BOOT" partition in MiB
    ayasuna__utilities__ingot__inputs__target_partitions_boot_size: 512
    # The size in MiB of the "DEPLOYMENT" partition; the "DATA" partition uses the remaining space
    ayasuna__utilities__ingot__inputs__target_partitions_deployment_size: 6144
    # How many ingot deployments to keep (including the current one), at least one
    ayasuna__utilities__ingot__inputs__target_partitions_deployment_history: 3
  tasks:
    - ansible.builtin.import_role:
        name: "ayasuna.utilities.ingot"
        tasks_from: "deploy.yml"

    - name: "[Deploy k8s ingot] Rebooting host"
      ansible.builtin.reboot:
        reboot_timeout: 300
```

In this example the role deploys the K8s ingot (built by the `Build k8s ingot` playbook above) to `/dev/sda`
on the host `k8s01`, together with the deployment arguments, keeps the last three deployments, and reboots
the host so that it boots into the ingot. The node deployed in this example is the cluster's bootstrap node.
To deploy additional cluster nodes, deploy the same ingot to those hosts with different arguments: a unique
`<k3s_node_name>` and `<k3s_node_ipv6_ip>` / `<k3s_node_ipv4_ip>`, and — for agent nodes —
`<k3s_node_type>: "agent"`. `<k3s_cluster_bootstrap_node_ip>` is set to the bootstrap node's IP on every node (including
the bootstrap node, for which it is its own IP; see [Cluster bootstrap](#cluster-bootstrap)).

### Boot

Boot the (U)EFI host from the device the ingot was deployed to. On every boot, the ingot's hooks configure
the node (hostname, users, SSH, firewall, network, iSCSI, K3s) and start the K3s node (see
[Behavior](#behavior)). All nodes keep their K3s state on the persistent `DATA` partition
(see [Persistence](#persistence)); so the bootstrap node only initializes the cluster during its first boot and
non-bootstrap nodes only try to join the cluster if they haven't joined it yet.

## Behavior

All hooks validate their inputs against the role's argument specification (see [Parameters](#parameters))
before doing anything else; if the validation fails, the hook fails.

**`install.yml`** — called once during the build. Performs a system upgrade (via APT, including an update of
the package lists and the removal of no-longer-needed packages, purging their configuration) and installs a
fixed set of packages (via the [`packages.yml` entrypoint of the `ayasuna.utilities.host`
role](../utilities/HOST.md#entrypoint-packagesyml)) — the entrypoint's default set (`openssh-server`,
`sudo`, `nftables`, `htop`, `iotop`, `nload`, `parted`, `iproute2`, `dnsutils`, `curl`, `bash-completion`,
`grep`) plus `nfs-common`, `open-iscsi`, `python3-kubernetes`, `python3-jsonpatch`, and `python3-yaml` — and
any additional packages given in `<packages>`. It then downloads the `k3s` binary of `<k3s_version>` (the
`amd64` variant) from the [K3s GitHub releases](https://github.com/k3s-io/k3s/releases) to
`/usr/local/bin/k3s` (mode `0755`), verifying its SHA-256 checksum.

**`local.yml`** — called on every boot, before networking. Performs the following, in order:

1. Sets the system hostname to `<name>` (via the [`hostname.yml` entrypoint of the `ayasuna.utilities.host`
   role](../utilities/HOST.md#entrypoint-hostnameyml)).
2. Sets up the users given in `<users>` (see [Users and SSH](#users-and-ssh)).
3. Writes the firewall configuration (see [Firewall](#firewall)).
4. Configures the SSH service, with the host keys stored in the persistent `/var/lib/ingot/data/ssh/`
   directory (see [Users and SSH](#users-and-ssh)).
5. Writes the network configuration for the WAN interface (see [Network](#network)).
6. Writes the iSCSI initiator name (see [iSCSI](#iscsi)).
7. Sets up K3s (see [K3s](#k3s)): the tool symlinks, the directories, the bind mounts from
   `/var/lib/ingot/data/` (which are started), and the `k3s.service` systemd unit.
8. Reloads the UDEV ruleset, triggers `add` events for all devices of the `net` subsystem (so that the
   interface renaming via the `.link` files from step 5 is applied to the already-existing devices), and
   waits up to 30 seconds for the UDEV event queue to become empty (via the
   [`ayasuna.utilities.udevadm` role](../utilities/UDEVADM.md)).

If `<debug>` is true, the hook additionally waits 30 seconds before completing (debug mode; see
[Parameters](#parameters)).

**`network.yml`** — called on every boot. Validates its inputs and performs no further actions.

**`final.yml`** — called at the end of every boot. Starts the `k3s.service` systemd unit (the unit is not
enabled; it is started by this hook on every boot), retrying up to 4 times with a 5-second delay between
attempts. For server nodes it additionally writes the `kubectl` bash completion to
`/etc/bash_completion.d/kubectl`, ensures that `/root/.kube/` exists, and symlinks
`/etc/rancher/k3s/k3s.yaml` to `/root/.kube/config`, so that `kubectl` works out of the box for the `root`
user.

**`test.yml`** — called once in the test VM during the build. Fails if `k3s.service` is not active. It then
runs a set of diagnostic commands and prints their output: `ip addr`, `nft list ruleset`,
`kubectl get nodes -o wide`, `kubectl get pods --all-namespaces`, `cat /etc/systemd/system/k3s.service`, and
`ls -la /root/.kube/`. Note that this hook assumes a server node (it uses `kubectl` and inspects
`/root/.kube/`).

## K3s

### Installation

The `k3s` binary is installed to `/usr/local/bin/k3s` during the build (see [Behavior](#behavior)). K3s
provides several tools via this single multiplexed binary; the `local.yml` hook therefore creates symlinks in
`/usr/local/bin/`:

- `crictl` and `ctr` — for all nodes.
- `kubectl` — for server nodes only.

### Service

The `local.yml` hook writes the `k3s.service` systemd unit to `/etc/systemd/system/k3s.service`:

- The service runs as `root` with `Type=notify` and `Restart=always` (5-second restart delay), and loads the
  `br_netfilter` and `overlay` kernel modules before starting K3s (best effort).
- The service is **not enabled**: the `final.yml` hook starts it on every boot (see
  [Behavior](#behavior)). It is ordered after the bind mounts from `/var/lib/ingot/data/` (see
  [Persistence](#persistence)) and after `network.target`.
- The service's start command is `/usr/local/bin/k3s <mode> <arguments>`, where `<mode>` is `server` or
  `agent` (depending on `<k3s_node_type>`) and `<arguments>` are derived from the role's inputs (see
  [Command line](#command-line) below).

### Command line

The `local.yml` hook derives the `k3s` command-line arguments from the inputs:

For **both** node types:

- `--node-ip <k3s_node_ipv6_ip>[,<k3s_node_ipv4_ip>]` — the node's IP address (es) (comma-separated if both
  are set).
- `--node-name <k3s_node_name>`
- `--flannel-iface wan0` — the Flannel CNI is pinned to the WAN interface (see [Network](#network)).
- `--token <k3s_cluster_token>`

For **server** nodes:

- `--cluster-init` — only if this node is the bootstrap node (see [Cluster bootstrap](#cluster-bootstrap)).
- `--cluster-cidr <k3s_cluster_ipv6_pod_network>[,<k3s_cluster_ipv4_pod_network>]` and
  `--service-cidr <k3s_cluster_ipv6_service_network>[,<k3s_cluster_ipv4_service_network>]`
- `--cluster-dns <ipv6_dns_ip>[,<ipv4_dns_ip>]` — derived from the service networks: for IPv6, `<prefix>::10` of the
  service network; for IPv4, `<a>.<b>.0.10` of the `<a>.<b>.0.0/16` service network.
- `--flannel-backend <k3s_cluster_flannel_backend>` — the `wireguard` choice maps to the `wireguard-native`
  backend.
- `--flannel-ipv6-masq` — only if the node has an IPv6 address.
- `--cluster-domain <k3s_cluster_domain>`
- `--disable <component>` — once per entry of `<k3s_cluster_disable>` (the packaged components K3s ships
  with, such as `traefik` or `coredns`).

For all nodes that are **not** the bootstrap node (regardless of node type):

- `--server https://[<k3s_cluster_bootstrap_node_ip>]:6443` — the API server of the bootstrap node (square
  brackets only for IPv6 addresses).

### Cluster bootstrap

A cluster has exactly one bootstrap node: the first server of the cluster. The bootstrap node is the node
whose `<k3s_node_ipv6_ip>` or `<k3s_node_ipv4_ip>` equals `<k3s_cluster_bootstrap_node_ip>`; it runs with
`--cluster-init`, initializing the cluster with K3s's embedded etcd. All other nodes — servers and
agents alike — join the cluster by connecting to the bootstrap node's API server
(`https://<k3s_cluster_bootstrap_node_ip>:6443`) using the token given in `<k3s_cluster_token>` (the K3s
["short" token format](https://docs.k3s.io/cli/token)).

The `<k3s_node_name>` must be unique within the cluster; it is also used as the node's iSCSI initiator name
(see [iSCSI](#iscsi)).

## Persistence

The ingot's root filesystem is an `overlayfs` that uses a `tmpfs` for the upper filesystem: everything the
boot hooks write to it is lost with a reboot. To persist the K3s state (and the SSH host keys), the
`local.yml` hook creates and starts (on every boot) systemd bind-mount units that mount subdirectories of
the persistent `/var/lib/ingot/data/` directory (see
[Directories](../utilities/INGOT.md#directories) in the ingot documentation):

| Mount unit              | Source (persistent)                   | Target              |
|-------------------------|---------------------------------------|---------------------|
| `var-lib-kubelet.mount` | `/var/lib/ingot/data/kubelet/`        | `/var/lib/kubelet/` |
| `var-lib-rancher.mount` | `/var/lib/ingot/data/rancher/data/`   | `/var/lib/rancher/` |
| `etc-rancher.mount`     | `/var/lib/ingot/data/rancher/config/` | `/etc/rancher/`     |

The mount units are ordered after the ingot's `var-lib-ingot-data.mount` unit (the mount of the `DATA`
partition), and `k3s.service` is ordered after the mounts. The SSH host keys are stored in
`/var/lib/ingot/data/ssh/` (see [Users and SSH](#users-and-ssh)).

Consequences:

- The K3s state of a node — including, for server nodes, the cluster's datastore (under
  `/var/lib/rancher/`) — persists across reboots and across redeployments of the ingot to the same host: a
  node comes back with its cluster membership (and, for the bootstrap node, the cluster itself) intact, as
  long as the `DATA` partition is preserved.
- Wiping the `DATA` partition (or deploying to a fresh device) resets the node's K3s state; for a server
  node, the cluster's datastore is then lost.

## Network

The `local.yml` hook writes `systemd-networkd` configuration files to `/etc/systemd/network/` that configure
a **bonded WAN interface** (`wan0`) from the physical interfaces given in `<wan_interfaces>`. The K3s Flannel
CNI is pinned to this interface (via `--flannel-iface wan0`), so the cluster's pod traffic uses it.

- **Interface renaming** — for each entry of `<wan_interfaces>`, an `00-wan0p<N>.link` file (with `N` the
  entry's index, starting at 0) matches the physical interface by its permanent MAC address (`<wan_interfaces[N].mac>`),
  renames it to `wan0p<N>`, and sets its MTU to `<wan_mtu>`.
- **Bond ports** — for each entry, an `00-wan0p<N>.network` file makes `wan0p<N>` a member of the `wan0`
  bond; the first entry is the bond's primary slave. The ports use no addressing of their own (no link-local
  addresses, DHCP, or router advertisements).
- **The bond** — `01-wan.netdev` creates `wan0` as an `active-backup` bond with `MIIMonitorSec=1s`,
  `PrimaryReselectPolicy=failure`, and MTU `<wan_mtu>`. If `<wan_mac>` is given, the bond always uses that
  MAC address (`FailOverMACPolicy=none`); otherwise the active port keeps its own MAC address
  (`FailOverMACPolicy=active`).
- **Addressing & routing** — `01-wan.network` configures `wan0`:
    - **IPv6** — a link-local address (EUI-64); if `<wan_accept_ra>` is true, router advertisements are
      accepted (which may additionally result in SLAAC addresses); the host does not send router
      advertisements, and the IPv6 privacy extensions are disabled.
    - **IPv4** — the static addresses from `<wan_ips>`; optionally, DHCPv4 (if `<wan_dhcp>` is true).
    - **DNS** — the static nameservers from `<wan_nameservers>`; LLMNR, mDNS, DNSSEC, and DNS-over-TLS are
      disabled.
    - **Routes** — the routes from `<wan_routes>` (table `main`, unicast, static, metric `128`; IPv4 routes
      additionally get `Scope=global`).

Note that the `local.yml` hook also triggers the UDEV `add` events for the network devices (see
[Behavior](#behavior)) so that the interface renaming via the `.link` files is applied to devices that already
exist when the hook runs.

## Firewall

The `local.yml` hook writes the nftables configuration to `/etc/nftables.conf` on every boot (via the
[`firewall.yml` entrypoint of the `ayasuna.utilities.host` role](../utilities/HOST.md#entrypoint-firewallyml));
the `nftables` service (enabled in the ingot) loads the file at boot after the hook has run.

The configuration uses the following presets (see the [HOST.md](../utilities/HOST.md#entrypoint-firewallyml)
documentation for their rules):

- `filter@log`
- `filter@forward.default`
- `filter@input.default`
- `filter@input.ssh`

In addition, the role defines the custom chains `USER_INPUT` and `USER_FORWARD` (the other user chains —
`USER_PREROUTING`, `USER_OUTPUT`, and `USER_POSTROUTING` — are empty):

- **`USER_INPUT`** — accepts:
    - Packets received on the CNI interfaces (`cni0`, `flannel*`) with a source address in the cluster's
      service and pod networks (for IPv6, additionally from the link-local range `fe80::/10`).
    - Input traffic on `wan0` destined for the node's own IP address, from the trusted networks
      (`<k3s_cluster_ipv6_trusted_networks>` for IPv6, `<k3s_cluster_ipv4_trusted_networks>` for IPv4).
- **`USER_FORWARD`** — accepts:
    - Packets received on the CNI interfaces with a source address in the cluster's service and pod networks (as above).
    - Forwarded traffic on `wan0` destined for the cluster's pod network (for both address families, and
      regardless of the trusted networks).

The resulting policies are:

- **Input** — policy `drop`: established flows, loopback traffic, safe ICMP/ICMPv6, SSH on port 22, and the
  K3s-related input traffic described above are accepted.
- **Forward** — policy `drop`: established flows, the CNI traffic, and the WAN-to-pod traffic described
  above are accepted.
- **Output** — policy `accept`.

## iSCSI

The `local.yml` hook writes `/etc/iscsi/initiatorname.iscsi` (mode `0600`) with
`InitiatorName=iqn.2025-09.com.ayasuna.iscsi:<k3s_node_name>`: every node gets an initiator name derived
from its (cluster-unique) node name, as multiple nodes logging into the same target with the same initiator
name can cause connection errors. The `open-iscsi` package is installed during the build, so the node can log
into iSCSI targets — for example, to use shared block storage.

## Users and SSH

`<users>` must contain at least one user, and the `root` user exactly once.

For each user in `<users>`, the `local.yml` hook performs the following on every boot (via the [`users.yml`
entrypoint of the `ayasuna.utilities.host` role](../utilities/HOST.md#entrypoint-usersyml)):

1. **Account** — creates (or updates) the user account with a login shell of `/bin/bash` and a home
   directory; the password is set (as a SHA-512 hash) on every run.
2. **SSH keys** — if the user has one or more public keys, the user's `~/.ssh/authorized_keys` file is
   managed **exclusively**: it contains exactly the given keys (one per line, in the form `<key_type>
   <key_content> <key_name>`), and any other keys are removed. The `~/.ssh` directory is managed as well.
3. **Sudo** — for every user except `root`, the file `/etc/sudoers.d/00-<user_name>` (mode `0440`, owned by
   `root:root`) is written, granting the user passwordless `sudo` (`<user_name> ALL=(ALL:ALL) NOPASSWD:ALL`).

The SSH service is configured on every boot via the [`ssh.yml` entrypoint of the `ayasuna.utilities.host`
role](../utilities/HOST.md#entrypoint-sshyml) with a hardened configuration: it listens on port `22` (on all
interfaces, IPv6 and IPv4), uses only public-key authentication (password authentication is disabled), and
denies root login. Therefore:

- The public keys of the `root` entry in `<users>` have no effect.
- To administer a node, connect via SSH as a non-root user (using one of their public keys) and use `sudo`
  to become `root`.
- The host keys are generated on first boot in `/var/lib/ingot/data/ssh/` (a persistent directory; existing
  keys are never overwritten). Unlike the ingot's default SSH setup (host keys baked into the ingot at build
  time), this means each host of a cluster keeps its own stable host keys across reboots and ingot
  deployments.

## Parameters

The role's hooks declare the following inputs (all using the prefix `ayasuna__ingot__k8s__inputs__`).

### Build

The `install.yml` hook declares the following inputs. They must be provided at build time (via
`ayasuna__utilities__ingot__inputs__build_ansible_role_arguments`):

- `ayasuna__ingot__k8s__inputs__k3s_version` (`str`, required) — the K3s version to install (a K3s release
  tag, for example `v1.32.5+k3s1`). The corresponding `amd64` `k3s` binary is downloaded (with SHA-256
  verification) from the K3s GitHub releases during the build.
- `ayasuna__ingot__k8s__inputs__packages` (`list[str]`, optional, default `[]`) — the additional APT
  packages to install during the build, in addition to the fixed set the role always installs (see
  [Behavior](#behavior)).

### Deploy

The `local.yml`, `network.yml`, `final.yml`, and `test.yml` entrypoints of the role declare the following
inputs:

- `ayasuna__ingot__k8s__inputs__debug` (`bool`, optional, default `false`) — whether to run in debug mode; if
  `true`, the `local.yml` hook additionally waits 30 seconds before completing.
- `ayasuna__ingot__k8s__inputs__name` (`str`, required) — the hostname to set on the system.
- `ayasuna__ingot__k8s__inputs__users` (`list[dict]`, required) — the users to set up/configure (see
  [Users and SSH](#users-and-ssh)). At least one user must be specified, and the `root` user exactly once.
  All users (except for `root`) will be able to become `root` by using `sudo`.
- `ayasuna__ingot__k8s__inputs__users[*].name` (`str`, required) — the user name.
- `ayasuna__ingot__k8s__inputs__users[*].password` (`str`, required) — the password of the user.
- `ayasuna__ingot__k8s__inputs__users[*].public_keys` (`list[dict]`, required) — the public keys to set up
  for the user (placed in the user's `~/.ssh/authorized_keys` file).
- `ayasuna__ingot__k8s__inputs__users[*].public_keys[*].name` (`str`, required) — the name of the public key.
- `ayasuna__ingot__k8s__inputs__users[*].public_keys[*].content` (`str`, required) — the contents of the
  public key.
- `ayasuna__ingot__k8s__inputs__users[*].public_keys[*].type` (`str`, required) — the public key type. One
  of: `ecdsa-sha2-nistp521`, `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp256`, `ssh-ed25519`, `ssh-rsa`.
- `ayasuna__ingot__k8s__inputs__wan_interfaces` (`list[dict]`, required) — the (physical) interfaces that are
  part of the active-backup bond that forms the WAN interface (see [Network](#network)). The first entry
  becomes the bond's primary slave.
- `ayasuna__ingot__k8s__inputs__wan_interfaces[*].mac` (`str`, required) — the MAC address of the (physical)
  interface that is part of the bond.
- `ayasuna__ingot__k8s__inputs__wan_mac` (`str`, optional, default `null`) — the MAC address the bond
  interface should use. If set, the `fail_over_mac` policy of the active-backup bond is `none` (the bond
  always uses this MAC address); otherwise it is `active` (the active port uses its own MAC address).
- `ayasuna__ingot__k8s__inputs__wan_mtu` (`int`, optional, default `1500`) — the MTU to use for the WAN
  interface as well as all interfaces that are part of the bond.
- `ayasuna__ingot__k8s__inputs__wan_ips` (`list[str]`, required) — the (static) IP addresses (CIDRs) to
  configure for the WAN interface.
- `ayasuna__ingot__k8s__inputs__wan_nameservers` (`list[str]`, required) — the (static) nameservers to
  configure for the WAN interface.
- `ayasuna__ingot__k8s__inputs__wan_dhcp` (`bool`, required) — whether DHCPv4 is enabled for the WAN
  interface. DHCPv6 is not explicitly configurable; if router advertisements are accepted, however, it might
  still be triggered by them (M-Flag, O-Flag).
- `ayasuna__ingot__k8s__inputs__wan_accept_ra` (`bool`, required) — whether IPv6 router advertisements are
  accepted on the WAN interface.
- `ayasuna__ingot__k8s__inputs__wan_routes` (`list[dict]`, required) — a set of additional routes to
  configure for the WAN interface.
- `ayasuna__ingot__k8s__inputs__wan_routes[*].to` (`str`, required) — the route target (CIDR).
- `ayasuna__ingot__k8s__inputs__wan_routes[*].via` (`str`, required) — the route gateway.
- `ayasuna__ingot__k8s__inputs__k3s_node_type` (`str`, required) — the K3s node type. One of: `server` (the
  node runs the K3s server), `agent` (the node runs the K3s agent).
- `ayasuna__ingot__k8s__inputs__k3s_node_name` (`str`, required) — the unique name of the node within the
  cluster (used as the K3s `--node-name` and as the node's iSCSI initiator name).
- `ayasuna__ingot__k8s__inputs__k3s_node_ipv4_ip` (`str`, optional, default `null`) — the IPv4 IP of the
  node. At least one of `<k3s_node_ipv4_ip>` and `<k3s_node_ipv6_ip>` must be specified; if this input is
  specified, all of the IPv4 cluster settings (`<k3s_cluster_ipv4_service_network>`,
  `<k3s_cluster_ipv4_pod_network>`, and `<k3s_cluster_ipv4_trusted_networks>`) must be specified as well —
  and vice versa.
- `ayasuna__ingot__k8s__inputs__k3s_node_ipv6_ip` (`str`, optional, default `null`) — the IPv6 IP of the
  node. At least one of `<k3s_node_ipv4_ip>` and `<k3s_node_ipv6_ip>` must be specified; if this input is
  specified, all of the IPv6 cluster settings (`<k3s_cluster_ipv6_service_network>`,
  `<k3s_cluster_ipv6_pod_network>`, and `<k3s_cluster_ipv6_trusted_networks>`) must be specified as well —
  and vice versa.
- `ayasuna__ingot__k8s__inputs__k3s_cluster_domain` (`str`, required) — the domain of the K8s cluster (for
  example `cluster.local`).
- `ayasuna__ingot__k8s__inputs__k3s_cluster_disable` (`list[str]`, optional, default `[]`) — the packaged
  components that K3s ships with to disable on the node. One of: `coredns`, `traefik`, `local-storage`,
  `metrics-server`, `servicelb`.
- `ayasuna__ingot__k8s__inputs__k3s_cluster_ipv4_service_network` (`str`, optional, default `null`) — the
  IPv4 network (CIDR) for the K8s services of the cluster. Must be a `/16` subnet.
- `ayasuna__ingot__k8s__inputs__k3s_cluster_ipv4_pod_network` (`str`, optional, default `null`) — the IPv4
  network (CIDR) for the K8s pods running on the cluster. Must be a `/16` subnet.
- `ayasuna__ingot__k8s__inputs__k3s_cluster_ipv4_trusted_networks` (`list[str]`, optional, default
  `["0.0.0.0/0"]`) — the trusted IPv4 networks (CIDRs): all IPv4 INPUT traffic from these networks, received
  on the WAN interface and destined for the node, is accepted (see [Firewall](#firewall)). Must at least
  contain the networks (or IPs) of the K8s nodes themselves, as they won't be able to communicate with each
  other otherwise. The default (any source) is only acceptable if the K8s nodes are not directly reachable via
  the internet. Note that, regardless of this setting, IPv4 traffic received on the WAN interface that is
  forwarded to the IPv4 pod network is always accepted.
- `ayasuna__ingot__k8s__inputs__k3s_cluster_ipv6_service_network` (`str`, optional, default `null`) — the
  IPv6 network (CIDR) for the K8s services of the cluster. Must be a `/112` subnet.
- `ayasuna__ingot__k8s__inputs__k3s_cluster_ipv6_pod_network` (`str`, optional, default `null`) — the IPv6
  network (CIDR) for the K8s pods running on the cluster. Must be a `/56` subnet.
- `ayasuna__ingot__k8s__inputs__k3s_cluster_ipv6_trusted_networks` (`list[str]`, optional, default
  `["::/0"]`) — the trusted IPv6 networks (CIDRs): all IPv6 INPUT traffic from these networks, received on
  the WAN interface and destined for the node, is accepted (see [Firewall](#firewall)). Must at least contain
  the networks (or IPs) of the K8s nodes themselves, as they won't be able to communicate with each other
  otherwise. The default (any source) is only acceptable if the K8s nodes are not directly reachable via the
  internet. Note that, regardless of this setting, IPv6 traffic received on the WAN interface that is
  forwarded to the IPv6 pod network is always accepted.
- `ayasuna__ingot__k8s__inputs__k3s_cluster_flannel_backend` (`str`, required) — the Flannel backend to use
  for the pod network. One of: `vxlan`, `wireguard` (which uses the `wireguard-native` backend).
- `ayasuna__ingot__k8s__inputs__k3s_cluster_token` (`str`, required) — the token the nodes use to join the
  cluster (the K3s ["short" token format](https://docs.k3s.io/cli/token)).
- `ayasuna__ingot__k8s__inputs__k3s_cluster_bootstrap_node_ip` (`str`, required) — the IPv6 or IPv4 IP of
  the node responsible for bootstrapping the cluster (the first server). It must be one of the
  `<k3s_node_ipv6_ip>` / `<k3s_node_ipv4_ip>` values of the cluster's nodes (see
  [Cluster bootstrap](#cluster-bootstrap)).

## References

- [argument_specs.yml](../../collections/ingot/roles/k8s/meta/argument_specs.yml) — the argument
  specification of the role, from which the inputs listed in the [Parameters](#parameters) section are
  derived.
- [INGOT.md](../utilities/INGOT.md) — the documentation of the `ayasuna.utilities.ingot` role, whose
  `build.yml` and `deploy.yml` entrypoints are used to build and deploy the K8s ingot.
- [HOST.md](../utilities/HOST.md) — the documentation of the `ayasuna.utilities.host` role, whose
  `packages.yml`, `hostname.yml`, `users.yml`, `ssh.yml`, and `firewall.yml` entrypoints the K8s ingot uses
  during the build and at boot.
- [UDEVADM.md](../utilities/UDEVADM.md) — the documentation of the `ayasuna.utilities.udevadm` role, which
  the `local.yml` hook uses to reload the UDEV ruleset and re-trigger the network devices.
- [K3s documentation](https://docs.k3s.io/) — the documentation of K3s, the lightweight Kubernetes
  distribution that the ingot runs.
- [K3s CLI: token](https://docs.k3s.io/cli/token) — the token formats K3s supports; `<k3s_cluster_token>` is
  expected in the "short" format.
- [K3s releases (GitHub)](https://github.com/k3s-io/k3s/releases) — the releases from which the
  `install.yml` hook downloads the `k3s` binary.

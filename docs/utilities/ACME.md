# Acme

The `ayasuna.utilities.acme` role manages ACME accounts and issues TLS certificates via the ACME (v2) protocol
([RFC 8555](https://datatracker.ietf.org/doc/html/rfc8555)), for example from Let's Encrypt. It provides two
entrypoints:

- `upsert_account.yml` — creates a new ACME account or updates an existing one.
- `upsert_certificate.yml` — creates a new TLS certificate for a DNS name, solving the ACME `dns-01` challenge by
  creating TXT records in a Hetzner Cloud DNS zone.

All ACME-related state (the account key, certificate keys, certificates, ...) is stored as files in
`<state_directory>` on the host the play runs on. The role creates the directory and its subdirectories if they
don't exist. The play must therefore run against the host on which the state should be kept, and that host
must have outbound HTTPS access to the ACME directory (and, for `upsert_certificate.yml`, to the Hetzner Cloud
API).

The role has no default entrypoint: `include_role` must specify `tasks_from` (see the Usage sections below).

The entrypoints require the `community.crypto` collection (which provides the ACME modules) and, for
`upsert_certificate.yml` additionally, the `hetzner.hcloud` collection (version 6.8.0 or newer).

## Entrypoint: `upsert_account.yml`

Creates a new ACME account or updates an existing one.

### Usage

The entrypoint is included like any other role entrypoint via `ansible.builtin.include_role` with `tasks_from`. Its
inputs are declared as variables using the prefix `ayasuna__utilities__acme__inputs__`:

```yaml
---
- name: "Upserting an ACME account"
  hosts: "targets"
  gather_facts: false
  tasks:
    - name: "Including the 'ayasuna.utilities.acme' role (upsert_account.yml)"
      ansible.builtin.include_role:
        name: "ayasuna.utilities.acme"
        tasks_from: "upsert_account.yml"
      vars:
        ayasuna__utilities__acme__inputs__password: "changeme"
        ayasuna__utilities__acme__inputs__state_directory: "/var/lib/acme"
        ayasuna__utilities__acme__inputs__acme_directory: "https://acme-v02.api.letsencrypt.org/directory"
        ayasuna__utilities__acme__inputs__account_email: "admin@example.com"
```

In this example the entrypoint creates (or updates) an ACME account for `admin@example.com` at the Let's Encrypt
*production* directory, storing the account key in `/var/lib/acme` on the target host.

Note that the default of `<acme_directory>` is the Let's Encrypt **staging** endpoint
(`https://acme-staging-v02.api.letsencrypt.org/directory`). Set it explicitly to the production endpoint if you
want production certificates.

### State

The entrypoint manages the following files on the target host:

- The directory `<state_directory>` and its `certificates/` subdirectory — created if they don't exist (mode
  0775).
- `<state_directory>/account.key` — the private key of the ACME account. Created only if it doesn't
  exist: an EC key on the P-384 curve, encrypted with `<password>` (mode 0600). The existing key is
  never overwritten or rotated, so the account stays the same across runs. If you change
  `<password>` you must delete the key first — a new key means a new account.

### Account

After the account key exists, the entrypoint upserts the ACME account at the directory given by
`<acme_directory>` (ACME v2):

- If no account exists for the key yet, the account is created, agreeing to the terms of service.
- If the account already exists, its contact is set to `mailto:<account_email>`.

### Parameters

The entrypoint declares the following inputs (all using the prefix `ayasuna__utilities__acme__inputs__`):

- `ayasuna__utilities__acme__inputs__password` (`str`, required) — the password to secure the account key with.
- `ayasuna__utilities__acme__inputs__state_directory` (`str`, required) — the directory in which ACME related
  state files are stored (account key). The directory will be created if it doesn't exist.
- `ayasuna__utilities__acme__inputs__acme_directory` (`str`, optional, default
  `https://acme-staging-v02.api.letsencrypt.org/directory`) — the ACME (v2) directory to use.
- `ayasuna__utilities__acme__inputs__account_email` (`str`, required) — the (contact) E-Mail to use for the
  account.

## Entrypoint: `upsert_certificate.yml`

Creates a new TLS certificate via the ACME protocol.

### Usage

The entrypoint is included like any other role entrypoint via `ansible.builtin.include_role` with `tasks_from`. Its
inputs are declared as variables using the prefix `ayasuna__utilities__acme__inputs__`:

```yaml
---
- name: "Issuing a certificate for www.example.com"
  hosts: "targets"
  gather_facts: false
  tasks:
    - name: "Including the 'ayasuna.utilities.acme' role (upsert_certificate.yml)"
      ansible.builtin.include_role:
        name: "ayasuna.utilities.acme"
        tasks_from: "upsert_certificate.yml"
      vars:
        ayasuna__utilities__acme__inputs__password: "changeme"
        ayasuna__utilities__acme__inputs__state_directory: "/var/lib/acme"
        ayasuna__utilities__acme__inputs__acme_directory: "https://acme-v02.api.letsencrypt.org/directory"
        ayasuna__utilities__acme__inputs__hetzner_api_token: "your-hetzner-api-token"
        ayasuna__utilities__acme__inputs__hetzner_api_endpoint: "https://api.hetzner.cloud/v1"
        ayasuna__utilities__acme__inputs__certificate_zone: "example.com"
        ayasuna__utilities__acme__inputs__certificate_primary_name: "www.example.com"
        ayasuna__utilities__acme__inputs__certificate_subject_alternative_names:
          - "example.com"
          - "mail.example.com"
        ayasuna__utilities__acme__inputs__certificate_renew_threshold: 25
```

In this example the entrypoint issues a certificate for `www.example.com` (plus the additional names
`example.com` and `mail.example.com`) from the Let's Encrypt *production* directory. The `dns-01` challenge is
solved by creating TXT records in the Hetzner Cloud DNS zone `example.com`.

Note that the default of `<acme_directory>` is the Let's Encrypt **staging** endpoint; set it
explicitly to the production endpoint if you want production certificates.

### Prerequisites

- An ACME account must already exist (the entrypoint uses its account key at `<state_directory>/account.key`
  and fails if it doesn't exist). Run the `upsert_account.yml` entrypoint first; both entrypoints must use the
  same values for `<state_directory>` and `<password>`.
- The DNS zone given by `<certificate_zone>` must exist in Hetzner Cloud, and
  `<hetzner_api_token>` must be allowed to manage the resource record sets of that zone.
- The target host must have outbound HTTPS access to both the ACME directory and the Hetzner Cloud API
  (`<hetzner_api_endpoint>`).
- The `openssl` binary must be available on the target host (it is used to decrypt the certificate key).

### Behavior

For the certificate whose primary name is given by `<certificate_primary_name>`, the entrypoint performs
the following steps. All files are located in `<state_directory>/certificates/`:

1. **Key** — creates the certificate private key `<certificate_primary_name>.key` (EC key on the
   P-384 curve, encrypted with `<password>`) if it doesn't exist.
2. **CSR** — creates the certificate signing request `<certificate_primary_name>.csr` if it doesn't
   exist. The common name is the value of `<certificate_primary_name>`; the subject alternative names
   are the primary name plus all entries of `<certificate_subject_alternative_names>` (each as a `DNS:`
   entry).
3. **Certificate** — requests the certificate from the ACME server, solving the `dns-01` challenge via Hetzner
   Cloud (see [DNS-01 challenge](#dns-01-challenge-hetzner-cloud)). The certificate is written to
   `<certificate_primary_name>.crt`, the intermediate chain to
   `<certificate_primary_name>-intermediate.crt`, and the full chain (certificate plus intermediate
   chain) to `<certificate_primary_name>-full.crt`.
4. **Outputs** — reads the certificate files back and exposes the certificate, the decrypted private key, and both
   chains as return values (see [Return values](#return-values)). This happens on every run, so the values are
   available even if no new certificate was issued.

The key and the CSR are only created if they don't exist; the existing ones are never overwritten. To rotate the
key or change the names of the certificate, delete the corresponding file (s) and run the entrypoint again.

### DNS-01 challenge (Hetzner Cloud)

When a (re)issue is required, the role requests a `dns-01` challenge from the ACME server for each name of the
CSR. The challenge is solved via Hetzner Cloud DNS:

1. For each challenge, the role creates a TXT record in the Hetzner Cloud DNS zone
   `<certificate_zone>` (TTL 60, the value quoted) at the record name of the challenge (e.g.
   `_acme-challenge.<name>`).
2. It then waits 15 seconds for the TXT records to propagate.
3. It validates the challenge with the ACME server and downloads the certificate.
4. Finally, the TXT records are removed again — even if the validation fails.

If the existing certificate is still valid (see [Renewal](#renewal)), no challenge is requested and no TXT records
are created.

### Renewal

The certificate is (re)issued in the following cases:

- The CSR was created or changed during this run (i.e. the first run for that name) — a new certificate is then
  issued regardless of the age of any existing certificate.
- The existing certificate is valid for less than `<certificate_renew_threshold>` days.

Otherwise the entrypoint does nothing ACME-related: no challenge is requested, no TXT records are created, and the
existing certificate files are left untouched. With the default threshold of 25 days and certificates that are
valid for 90 days, a daily run renews the certificate roughly every 65 days.

### State

The entrypoint manages the following files on the target host for the certificate whose primary name is given by
`<certificate_primary_name>` (all files are under `<state_directory>/certificates/`):

- `<certificate_primary_name>.key` — the private key of the certificate (EC P-384, encrypted with
  `<password>`). Created only if it doesn't exist.
- `<certificate_primary_name>.csr` — the certificate signing request. Created only if it doesn't
  exist.
- `<certificate_primary_name>.crt` — the issued certificate (PEM).
- `<certificate_primary_name>-intermediate.crt` — the intermediate certificate chain (PEM).
- `<certificate_primary_name>-full.crt` — the full chain: certificate plus intermediate chain (PEM).

### Parameters

The entrypoint declares the following inputs (all using the prefix `ayasuna__utilities__acme__inputs__`):

- `ayasuna__utilities__acme__inputs__password` (`str`, required) — the password to secure the account &
  certificate key with.
- `ayasuna__utilities__acme__inputs__state_directory` (`str`, required) — the directory in which ACME related
  state files are stored (account key, certificate private key, ...). The directory will be created if it
  doesn't exist.
- `ayasuna__utilities__acme__inputs__acme_directory` (`str`, optional, default
  `https://acme-staging-v02.api.letsencrypt.org/directory`) — the ACME (v2) directory to use.
- `ayasuna__utilities__acme__inputs__hetzner_api_token` (`str`, required) — the Hetzner Cloud API token to use.
- `ayasuna__utilities__acme__inputs__hetzner_api_endpoint` (`str`, optional, default `https://api.hetzner.cloud/v1`)
  — the Hetzner Cloud API endpoint to use.
- `ayasuna__utilities__acme__inputs__certificate_zone` (`str`, required) — the name of the (Hetzner) DNS zone to
  add the TXT records to so that the ACME challenge can be solved.
- `ayasuna__utilities__acme__inputs__certificate_primary_name` (`str`, required) — the primary (DNS) name of the
  certificate, which will be used as the common name of the certificate.
- `ayasuna__utilities__acme__inputs__certificate_subject_alternative_names` (`list[str]`, required) — the
  subject alternative names (SANs) of the certificate, in addition to the primary name (which is always included
  as a SAN).
- `ayasuna__utilities__acme__inputs__certificate_renew_threshold` (`int`, optional, default `25`) — the
  certificate is renewed if it is valid for less than the specified number of days.

### Return values

The entrypoint sets the following variables (all using the prefix `ayasuna__utilities__acme__outputs__`) on the
host the play runs on; tasks that run later on the same host can use them directly, and other hosts can access
them via `hostvars`:

- `ayasuna__utilities__acme__outputs__certificate` (`str`) — the issued certificate (PEM, the contents of
  `<certificate_primary_name>.crt`).
- `ayasuna__utilities__acme__outputs__private_key` (`str`) — the private key of the certificate (PEM, decrypted).
- `ayasuna__utilities__acme__outputs__full_chain` (`str`) — the full chain: certificate plus intermediate chain (PEM,
  the contents of `<certificate_primary_name>-full.crt`).
- `ayasuna__utilities__acme__outputs__intermediate_chain` (`str`) — the intermediate certificate chain (PEM, the
  contents of `<certificate_primary_name>-intermediate.crt`).

## References

- [argument_specs.yml](../../collections/utilities/roles/acme/meta/argument_specs.yml) — The argument
  specification of the role, from which the inputs listed in the Parameters sections are derived.
- [RFC 8555 (Automatic Certificate Management Environment)](https://datatracker.ietf.org/doc/html/rfc8555) — The
  specification of the ACME protocol (v2) that the role uses.
- [Let's Encrypt](https://letsencrypt.org/) — A widely used ACME (v2) certificate authority; both the default (staging)
  and the production value of `<acme_directory>` are its directories.
- [Let's Encrypt staging environment](https://letsencrypt.org/docs/staging-environment/) — Documentation of the
  Let's Encrypt staging endpoint that is the default of `<acme_directory>`.
- [Hetzner Cloud DNS](https://docs.hetzner.com/networking/dns/) — Documentation of the Hetzner Cloud DNS API that
  is used to create the TXT records for the `dns-01` challenge.
- [community.crypto.acme_account (Ansible documentation)](https://docs.ansible.com/projects/ansible/latest/collections/community/crypto/acme_account_module.html) —
  The module that creates and updates the ACME account.
- [community.crypto.acme_certificate (Ansible documentation)](https://docs.ansible.com/projects/ansible/latest/collections/community/crypto/acme_certificate_module.html) —
  The module that requests the certificate and handles the ACME challenges.
- [hetzner.hcloud.zone_rrset (Ansible documentation)](https://docs.ansible.com/projects/ansible/latest/collections/hetzner/hcloud/zone_rrset_module.html) —
  The module that manages the TXT records of the Hetzner Cloud DNS zone.

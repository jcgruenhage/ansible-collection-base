# OpenPGP Secret Store

The **openpgp_secretstore** module and lookup manage secrets in a
[`pass`](https://www.passwordstore.org/)-compatible store: encrypted files under
a directory, with recipients defined by `.gpg-id` files (same layout and
semantics as `pass`).

## Backends

Two backends are supported:

| Backend | Description |
|---------|-------------|
| **GnuPG** | Calls the `gpg` binary via subprocess, using the default GnuPG keyring. |
| **SOP** | Uses a [Stateless OpenPGP](https://datatracker.ietf.org/doc/draft-dkg-openpgp-stateless-cli/) CLI (e.g. [`rsop`](https://gitlab.com/sirpent-technology/rsop)). Requires a decryption key file and a [PGP cert-d](https://sequoia-pgp.gitlab.io/pgp-cert-d/) certificate store. Supports separate executables for encryption and decryption (useful for hardware-backed keys). |

Backend selection is **automatic** when not explicitly configured: if a
decryption key and SOP executables are present, SOP is used; otherwise GnuPG.
You can force a backend by setting `backend` in the config file or
`ANSIBLE_OPENPGP_SECRETSTORE_BACKEND` in the environment.

## Configuration

Backend and SOP options are set **only via config file or environment** — never
as task parameters. The config file path is platform-specific:

| Platform | Path |
|----------|------|
| Linux | `$XDG_CONFIG_HOME/ansible-openpgp-secretstore/config.yaml` (default `~/.config/…`) |
| macOS | `~/Library/Application Support/ansible-openpgp-secretstore/config.yaml` |
| Windows | `%APPDATA%\ansible-openpgp-secretstore\config.yaml` |

Environment variables use the prefix `ANSIBLE_OPENPGP_SECRETSTORE_` and
override the config file. See
[docs/openpgp-secretstore-config.example.yaml](docs/openpgp-secretstore-config.example.yaml)
for a commented example with all available options and their env overrides.

### Config reference

```yaml
# Backend: "gnupg" or "sop". Omit to auto-select.
# Env: ANSIBLE_OPENPGP_SECRETSTORE_BACKEND
backend: sop

# Default password store path (module/lookup can override per task).
# Env: ANSIBLE_OPENPGP_SECRETSTORE_PASSWORD_STORE_PATH
password_store_path: ~/.password-store

sop:
  # Default SOP binary (used for both encrypt and decrypt unless overridden).
  # Env: ANSIBLE_OPENPGP_SECRETSTORE_SOP_EXEC
  exec: rsop

  encryption:
    # Binary for encryption (falls back to sop.exec).
    # Env: ANSIBLE_OPENPGP_SECRETSTORE_SOP_ENCRYPTION_EXEC
    exec: rsop
    # PGP cert-d certificate store.
    # Env: PGP_CERT_D or ANSIBLE_OPENPGP_SECRETSTORE_SOP_ENCRYPTION_PGP_CERT_D
    pgp_cert_d: ~/.local/share/pgp.cert.d

  decryption:
    # Binary for decryption (e.g. rsoct for hardware-backed keys).
    # Env: ANSIBLE_OPENPGP_SECRETSTORE_SOP_DECRYPTION_EXEC
    exec: rsop
    # Secret key file (required for SOP).
    # Env: ANSIBLE_OPENPGP_SECRETSTORE_SOP_DECRYPTION_KEY
    key: ~/.config/ansible-openpgp-secretstore/secret-key.asc
    # Key passphrase (optional; passed via CLI, may appear in process listings).
    # Env: ANSIBLE_OPENPGP_SECRETSTORE_SOP_DECRYPTION_PASSWORD
    password: ""
```

## Store layout

The store follows the `pass` convention:

```
~/.password-store/
├── .gpg-id                        # recipients (fingerprints, one per line)
├── servers/
│   ├── .gpg-id                    # optional override for this subtree
│   ├── prod/
│   │   └── db_password.gpg        # encrypted secret
│   └── staging/
│       └── db_password.gpg
└── services/
    └── api_key.gpg
```

- **`.gpg-id`** files list recipient fingerprints (or key IDs), one per line.
  The store walks up from the secret's directory to find the nearest `.gpg-id`.
- Encrypted files use the `.gpg` extension.
- When `commit_changes` is enabled (the module enables it by default), changes
  are committed to a git repository at the store root (if one exists).

## Module usage

```yaml
- name: Generate secret if it does not exist
  famedly.base.openpgp_secretstore:
    password_slug: example/secret
  delegate_to: localhost

- name: Force regenerate (rotate) a secret
  famedly.base.openpgp_secretstore:
    password_slug: example/overwrite
    overwrite: true
  delegate_to: localhost

- name: Generate secret from command output
  famedly.base.openpgp_secretstore:
    password_slug: example/bin
    secret_type: binary
    secret_binary: openssl rand -hex 32
  delegate_to: localhost

- name: Store a user-supplied secret
  famedly.base.openpgp_secretstore:
    password_slug: example/user
    secret_type: user_supplied
    user_supplied_secret: "{{ vault_my_secret }}"
  delegate_to: localhost

- name: Read a JSON secret
  famedly.base.openpgp_secretstore:
    password_slug: example/json
    data_type: json
  delegate_to: localhost
```

### Module parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `password_store_path` | str | `~/.password-store/` | Path to the password store directory. |
| `password_slug` | str | *(required)* | Secret path/slug (e.g. `servers/prod/db_password`). |
| `state` | str | `present` | `present` or `absent`. |
| `data_type` | str | `plain` | `plain`, `json`, or `yaml`. |
| `secret_type` | str | `random` | How to generate: `random`, `binary`, or `user_supplied`. |
| `secret_length` | int | `20` | Length of random secrets. |
| `secret_pattern` | str | `([A-Za-z0-9])` | Regex character class for random secrets. |
| `secret_binary` | str | — | Shell command whose stdout becomes the secret (`secret_type: binary`). |
| `user_supplied_secret` | str | — | Literal secret value (`secret_type: user_supplied`). |
| `overwrite` | bool | `false` | Force regeneration of the secret. |
| `check_recipients` | bool | `true` | Verify ciphertext recipients match `.gpg-id`; re-encrypt if mismatched. |
| `secret_fact` | str | — | If set, store the secret as an Ansible fact under this key. |

### Return values

| Key | Description |
|-----|-------------|
| `secret` | Decrypted secret (string for `plain`, structure for `json`/`yaml`). |
| `action` | Operation performed: `generate`, `delete`, `regenerate`, or `reencrypt`. |
| `changed` | Whether the store was modified. |
| `diff` | Before/after recipient key IDs (useful with `--diff`). |

## Lookup usage

```yaml
- name: Read a secret via lookup
  debug:
    var: mypassword
  vars:
    mypassword: "{{ lookup('famedly.base.openpgp_secretstore', 'example/secret') }}"

- name: Read and parse as YAML
  debug:
    var: mypassword
  vars:
    mypassword: "{{ lookup('famedly.base.openpgp_secretstore', 'example/yaml', data_type='yaml') }}"

- name: Read from a custom store path
  debug:
    var: mypassword
  vars:
    mypassword: "{{ lookup('famedly.base.openpgp_secretstore', 'example/secret', password_store_path='/tmp/store') }}"
```

The lookup accepts `password_store_path`, `data_type`, and `check_recipients`
as keyword arguments. If the secret does not exist, the lookup generates a
random plain secret by default (same as the module with defaults).

## Recipient management

Recipients are determined solely by `.gpg-id` files in the store (pass
semantics). The store walks up from the encrypted file's directory until it
finds a `.gpg-id`.

When `check_recipients` is enabled (the default), the module compares the
key IDs embedded in the ciphertext against the fingerprints in `.gpg-id`. If
they don't match — for example after adding or removing a recipient — the secret
is decrypted and re-encrypted to the current recipient set. The SOP backend
resolves fingerprints to certificate files via the PGP cert-d store; the GnuPG
backend resolves them from its default keyring.

## Dependencies

- **PyYAML** >= 6.0
- **dataclass-wizard** (with yaml extra)
- **filelock** >= 3.0.12
- **GitPython** >= 3.1.24
- **PGPy** >= 0.6.0

For the SOP backend, you also need a SOP-compatible binary (e.g. `rsop`).

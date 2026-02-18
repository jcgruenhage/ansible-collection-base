# `famedly.base` ansible collection

![Matrix](https://img.shields.io/matrix/ansible-famedly:matrix.org)

## Scope

This ansible collection contains a variety of basic/barebone functionality
needed for bootstrapping larger, complex infrastructure. This includes
roles for databases (like redis, ldap, postgres) as they are often a foundation
to build services on.

## Roles

- [`roles/dropbear_luks_unlock`](roles/dropbear_luks_unlock/README.md) for setting up dropbear to unlock LUKS volumes using a SSH connection at boot
- [`roles/hostname`](roles/hostname/README.md) for setting `/etc/hostname` and `/etc/hosts`
- [`roles/ldap`](roles/ldap/README.md) to deploy openldap in a docker container
- [`roles/rclone_serve`](roles/rclone_serve/README.md) to deploy rclone serve in a docker container
- [`roles/redis`](roles/redis/README.md) to deploy redis in a docker container
- [`roles/restic`](roles/restic/README.md) to configure backups using restic controlled by systemd
- [`roles/sshd`](roles/sshd/README.md) for SSH hardening
- [`roles/user`](roles/user/README.md) for creating user accounts with SSH keys deployed

## Plugins

### Modules

- **`openpgp_secretstore`** — save and retrieve secrets from a [`pass`](https://www.passwordstore.org/)-compatible store with GnuPG or SOP backends. See [SECRETSTORE.md](SECRETSTORE.md) for details.

### Lookups

- **`openpgp_secretstore`** — read-only lookup for the same store. See [SECRETSTORE.md](SECRETSTORE.md).

### Filters

- **`consensus`** — assert all values in a dict are equal; return the common value
- **`split2multidict`** — split lines into a multidict (key → list of values)
- **`regex_replace`** — regex substitution with optional required-match count
- **`reject_keys`** — remove specified keys from a dict
- **`select_keys`** — keep only specified keys from a dict
- **`intersect`** — ordered set intersection of two lists

## Testing

See **[TESTING.md](TESTING.md)** for unit and integration test instructions.

## License

[AGPL-3.0-only](LICENSE.md)

## Authors

- Jadyn Emma Jäger <jadyn@jadyn.dev>
- Jan Christian Grünhage <jan.christian@gruenhage.xyz>
- Johanna Dorothea Reichmann <transcaffeine@finallycoffee.eu>
- Vincent Wilke <v.wilke@famedly.com>

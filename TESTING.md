# Testing

The test suite covers linting, unit tests (Python 3.12, 3.13, and 3.14), and
integration tests. All commands are wrapped in `make` targets for convenience.

## Setup

`ansible-test` requires the collection to live under a path that contains
`ansible_collections`. With the default clone, the repo uses a symlink so the
resolved path does not satisfy that. Clone into the expected layout first:

```bash
mkdir -p ansible_collections/famedly
git clone https://github.com/famedly/ansible-collection-base.git ansible_collections/famedly/base
cd ansible_collections/famedly/base
```

Then sync dependencies:

```bash
make venv
```

## Linting

```bash
make lint
```

This runs `ruff format --check`, `ruff check`, `ty check`, and
`ansible-test sanity`.

## Tests

```bash
make test
```

This runs `ansible-test units` and `ansible-test integration`.

## Integration tests

Integration tests follow the [Ansible collection integration test](https://docs.ansible.com/projects/ansible/latest/community/collection_contributors/collection_integration_about.html)
layout: they are playbooks that invoke modules and assert on results. The
target `openpgp_secretstore_sop` in `tests/integration/targets/openpgp_secretstore_sop/`
tests the `openpgp_secretstore` module with the SOP backend: it uses **rsop**
to generate keys and certs, sets up a cert store and `.gpg-id`, then runs the
module and asserts idempotency and that the encrypted file exists. It also
initializes a git repository in the store and verifies that re-encryption,
overwrite, and deletion each produce a new git commit.

The target skips gracefully when the `rsop` binary is not available. To
install rsop:

```bash
cargo install rsop
```

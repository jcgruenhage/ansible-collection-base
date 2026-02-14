# Testing

All commands run through `uv run`. The test suite covers linting, unit tests
(Python 3.12, 3.13, and 3.14), and integration tests.

## Setup

`ansible-test` requires the collection to live under a path that contains
`ansible_collections`. With the default clone, the repo uses a symlink so the
resolved path does not satisfy that. Clone into the expected layout first:

```bash
mkdir -p ansible_collections/famedly
git clone https://github.com/famedly/ansible-collection-base.git ansible_collections/famedly/base
cd ansible_collections/famedly/base
```

Then sync dependencies for both Python versions:

```bash
uv sync -p 3.12
uv sync -p 3.13
uv sync -p 3.14
```

## Linting

```bash
uv run ruff format --check .
uv run ruff check .
uv run ty check
uv run ansible-test sanity
```

## Unit tests

Re-sync for the target Python version before each run (required for
`ansible-test` to pick up the correct environment):

```bash
uv sync -p 3.12
uv run ansible-test units --python 3.12

uv sync -p 3.13
uv run ansible-test units --python 3.13

uv sync -p 3.14
uv run ansible-test units --python 3.14
```

## Integration tests

Integration tests follow the [Ansible collection integration test](https://docs.ansible.com/projects/ansible/latest/community/collection_contributors/collection_integration_about.html) layout: they are playbooks that invoke modules and assert on results. The target `openpgp_secretstore_sop` in `tests/integration/targets/openpgp_secretstore_sop/` tests the openpgp_secretstore module with the SOP backend: it uses **rsop** to generate a key and cert, sets up a cert store and `.gpg-id`, then runs the module and asserts idempotency and that the encrypted file exists. Run with:

```bash
cargo install rsop
uv run ansible-test integration openpgp_secretstore_sop
```

The target skips when the `rsop` binary is not available.

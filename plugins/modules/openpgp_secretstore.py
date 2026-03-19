#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2026, JC Grünhage
# GNU Affero General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/agpl-3.0.txt)

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: openpgp_secretstore
author:
    - Jan Christian Grünhage (@jcgruenhage)
short_description: Save and retrieve secrets from pass-compatible encrypted files
description:
    - Save and retrieve secrets from a pass-compatible password store (U(https://www.passwordstore.org/)).
    - >
      Supports two backends C(gnupg) (GnuPG subprocess) and C(sop) (Stateless OpenPGP CLI).
      The backend is chosen automatically; SOP is used when a decryption key and SOP
      executables are configured, otherwise GnuPG is used.
    - >
      Backend and SOP behaviour are configured only outside the module, via environment
      variables or a config file. Prefix C(ANSIBLE_OPENPGP_SECRETSTORE). See collection README.
    - Recipients for a path come from the C(.gpg-id) file only (pass semantics). No keyring path option.
    - Secrets can be plain text, JSON, or YAML; generated secrets can be random, from a command, or user-supplied.
requirements:
    - PyYAML >= 6.0
    - dataclass-wizard (with yaml extra)
    - filelock >= 3.0.12
    - GitPython >= 3.1.24
    - PGPy >= 0.6.0
options:
    password_store_path:
        description: Path to the password store directory.
        type: str
        default: ~/.password-store/
    password_slug:
        description: >
            Secret path/slug (e.g. C(servers/prod/some_secret)) used to locate the encrypted file.
            Compatible with the pass utility.
        required: true
        type: str
    state:
        description: Whether the secret file should exist.
        type: str
        choices: [present, absent]
        default: present
    data_type:
        description: Data type of the encrypted content (plain, json, or yaml).
        type: str
        choices: [plain, yaml, json]
        default: plain
    secret_fact:
        description: >
            If set and state is present, the secret is stored under this key as an Ansible fact.
            "WARNING: If you have a persistent cache, the secret may be cached in plain text."
        type: str
    overwrite:
        description: Force regeneration of the secret (re-generate and overwrite).
        type: bool
        default: false
    secret_type:
        description: How to generate a new secret when the file is missing or overwrite is true.
        type: str
        choices: [random, binary, user_supplied]
        default: random
    secret_binary:
        description: >
            When secret_type is binary, this command is run and its STDOUT is used as the secret.
            Set data_type to yaml or json if the command outputs structured data.
        type: str
    secret_length:
        description: When secret_type is random, length of the generated string.
        type: int
        default: 20
    secret_pattern:
        description: When secret_type is random, regex pattern for allowed characters.
        type: str
        default: "([A-Za-z0-9])"
    user_supplied_secret:
        description: When secret_type is user_supplied, this value is used as the secret.
        type: str
    check_recipients:
        description: When present, verify ciphertext recipients match .gpg-id and re-encrypt if not.
        type: bool
        default: true
"""

EXAMPLES = r"""
- name: Generate secret if it does not exist
  famedly.base.openpgp_secretstore:
    password_slug: example/secret
  delegate_to: localhost

- name: Force regenerate secret
  famedly.base.openpgp_secretstore:
    password_slug: example/overwrite
    overwrite: true
  delegate_to: localhost

- name: Generate secret from command output
  famedly.base.openpgp_secretstore:
    password_slug: example/bin
    secret_type: binary
    secret_binary: ip a
  delegate_to: localhost

- name: Read JSON secret
  famedly.base.openpgp_secretstore:
    password_slug: example/json
    data_type: json
  delegate_to: localhost

- name: Read YAML secret
  famedly.base.openpgp_secretstore:
    password_slug: example/yaml
    data_type: yaml
  register: yaml_result
"""

RETURN = r"""
secret:
    description: >
      Decrypted secret (loaded or newly generated). For json/yaml data_type this is a structure, not a string.
    type: raw
    returned: when state is present
action:
    description: >
      Operation performed: C(generate) (new secret), C(delete) (removed), C(regenerate) (rotated/overwritten), C(reencrypt) (recipients fixed).
    type: str
    returned: when changed
password_slug:
    description: The password slug.
    type: str
    returned: always
diff:
    description: Before/after recipient key IDs when recipients changed or secret was added/removed.
    type: dict
    returned: when changed
message:
    description: Human-readable message about the task.
    type: str
    returned: when changed
warning:
    description: Warnings (e.g. recipient mismatch, re-encrypted).
    type: list
    returned: when present
"""


import traceback
from pathlib import Path
from typing import Any, Dict, List

from ansible.module_utils.basic import AnsibleModule, missing_required_lib

SECRETSTORE_IMP_ERR = None
try:
    from ansible_collections.famedly.base.plugins.module_utils.secretstore import (
        SecretStore,
    )
    from ansible_collections.famedly.base.plugins.module_utils.util.generate import (
        SecretGenerator,
    )

    HAS_SECRETSTORE = True
except ImportError:
    HAS_SECRETSTORE = False
    SECRETSTORE_IMP_ERR = traceback.format_exc()


def _argument_spec() -> Dict[str, Any]:
    """Task-level options only; backend/SOP from config/env."""
    return {
        "password_store_path": dict(
            type="str",
            default="~/.password-store/",
            no_log=False,
        ),
        "password_slug": dict(type="str", required=True, no_log=False),
        "state": dict(
            type="str",
            choices=["present", "absent"],
            default="present",
        ),
        "data_type": dict(
            type="str",
            choices=["plain", "yaml", "json"],
            default="plain",
        ),
        "secret_fact": dict(type="str", default=None, no_log=False),
        "overwrite": dict(type="bool", default=False),
        "secret_type": dict(
            type="str",
            choices=["random", "binary", "user_supplied"],
            default="random",
            no_log=False,
        ),
        "secret_binary": dict(type="str", default=None, no_log=False),
        "secret_length": dict(type="int", default=20, no_log=False),
        "secret_pattern": dict(type="str", default="([A-Za-z0-9])", no_log=False),
        "user_supplied_secret": dict(type="str", default=None, no_log=True),
        "check_recipients": dict(type="bool", default=True),
    }


def main() -> None:
    module = AnsibleModule(
        argument_spec=_argument_spec(),
        supports_check_mode=True,
    )
    params = module.params
    warnings: List[str] = []

    if not HAS_SECRETSTORE:
        module.fail_json(
            msg=missing_required_lib(
                "famedly.base secretstore (PyYAML, dataclass-wizard, filelock, GitPython, PGPy)"
            ),
            exception=SECRETSTORE_IMP_ERR,
        )

    from ansible_collections.famedly.base.plugins.module_utils.util import (
        MISSING_IMPORTS,
    )

    if MISSING_IMPORTS:
        libs = ", ".join(sorted(MISSING_IMPORTS))
        module.fail_json(msg=missing_required_lib(libs))

    try:
        store = SecretStore(
            password_store_path=Path(params["password_store_path"])
            if params.get("password_store_path")
            else None,
            generate=SecretGenerator(
                secret_type=params.get("secret_type", "random"),
                data_type=params.get("data_type", "plain"),
                length=params.get("secret_length", 20),
                letter_pattern=params.get("secret_pattern", "([A-Za-z0-9])"),
                binary=params.get("secret_binary"),
                user_supplied_secret=params.get("user_supplied_secret"),
            ),
        )
    except (RuntimeError, ValueError) as e:
        module.fail_json(msg="Backend or store setup failed: %s" % e)

    state = params.get("state", "present")
    password_slug = params["password_slug"]
    try:
        er = store.ensure(
            password_slug,
            state=state,
            overwrite=params.get("overwrite", False),
            check_mode=module.check_mode,
            check_recipients=params.get("check_recipients", True),
            commit_changes=True,
        )
    except (ValueError, ImportError, RuntimeError, FileNotFoundError) as e:
        module.fail_json(msg=str(e))

    result = {
        "changed": er.changed,
        "message": er.message,
        "warning": list(warnings) + list(er.warning),
        "password_slug": password_slug,
        "ansible_facts": {},
        "diff": {
            "before_header": "%s gpg recipients" % password_slug,
            "after_header": "%s gpg recipients" % password_slug,
            "before": er.diff_before,
            "after": er.diff_after,
        },
    }
    if er.action is not None:
        result["action"] = er.action
    if er.secret is not None:
        result["secret"] = er.secret
    if params.get("secret_fact") and er.secret is not None:
        result["ansible_facts"][params["secret_fact"]] = er.secret

    if result["message"]:
        module.log(result["message"])
    for w in result["warning"]:
        module.warn(w)

    result["diff"]["before"] = "\n".join(result["diff"]["before"]) + "\n"
    result["diff"]["after"] = "\n".join(result["diff"]["after"]) + "\n"

    module.exit_json(**result)


if __name__ == "__main__":
    main()

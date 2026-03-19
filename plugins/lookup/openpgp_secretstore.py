#!/usr/bin/env python
# -*- coding: utf-8 -*-

# (c) 2026, JC Grünhage
# GNU Affero General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/agpl-3.0.txt)

DOCUMENTATION = r"""
---
name: openpgp_secretstore
author:
    - Jan Christian Grünhage (@jcgruenhage)
short_description: Read secrets from a pass-compatible store (backend from config)
description:
  - Read passwords/secrets from a pass-compatible password store (U(https://www.passwordstore.org/)).
  - "Backend (gnupg or sop) is chosen by config: SOP when decryption key and executables are set
    (encryption C(sop.encryption.exec) or C(sop.exec); decryption C(sop.decryption.exec) or C(sop.exec)), else GnuPG."
  - Backend and SOP options are set via config file or environment variables only.
  - Supports plain, YAML, and JSON data types.
requirements:
  - PyYAML >= 6.0
  - dataclass-wizard (with yaml extra)
  - filelock >= 3.0.12
  - GitPython >= 3.1.24
  - PGPy >= 0.6.0
options:
  _terms:
    description: Slug of the secret to read from the store.
    required: true
  password_store_path:
    description: Path to the password store directory.
    default: '~/.password-store'
  data_type:
    description: Interpret decrypted data as plain, yaml, or json.
    default: 'plain'
    choices: [plain, yaml, json]
  check_recipients:
    description: Whether to verify ciphertext recipients match .gpg-id (and re-encrypt if not).
    default: true
"""

EXAMPLES = r"""
- name: Lookup secret (openpgp_secretstore)
  debug:
    var: mypassword
  vars:
    mypassword: "{{ lookup('famedly.base.openpgp_secretstore', 'example') }}"

- name: Lookup and parse as YAML
  debug:
    var: mypassword
  vars:
    mypassword: "{{ lookup('famedly.base.openpgp_secretstore', 'example/yaml', data_type='yaml') }}"

- name: Lookup from custom store path
  debug:
    var: mypassword
  vars:
    mypassword: "{{ lookup('famedly.base.openpgp_secretstore', 'example/secret', password_store_path='/tmp/store') }}"
"""

RETURN = r"""
_raw:
  description: The decrypted secret (string or structure for json/yaml).
  type: raw
"""


import traceback
from pathlib import Path

from ansible.errors import AnsibleError
from ansible.module_utils.basic import missing_required_lib
from ansible.plugins.lookup import LookupBase

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


class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs):
        if not terms:
            raise AnsibleError(
                "openpgp_secretstore lookup requires a secret slug (term)"
            )
        term = terms[0]
        password_store_path = kwargs.get("password_store_path", "~/.password-store")
        data_type = kwargs.get("data_type", "plain")
        check_recipients = kwargs.get("check_recipients", True)

        if not HAS_SECRETSTORE:
            raise AnsibleError(
                "%s\n%s"
                % (
                    missing_required_lib(
                        "famedly.base secretstore (PyYAML, dataclass-wizard, filelock, GitPython, PGPy)"
                    ),
                    SECRETSTORE_IMP_ERR or "",
                )
            )

        from ansible_collections.famedly.base.plugins.module_utils.util import (
            MISSING_IMPORTS,
        )

        if MISSING_IMPORTS:
            libs = ", ".join(sorted(MISSING_IMPORTS))
            raise AnsibleError(
                missing_required_lib(libs)
            )

        try:
            store = SecretStore(
                password_store_path=Path(password_store_path)
                if password_store_path
                else None,
                generate=SecretGenerator(data_type=data_type),
            )
        except ValueError as e:
            raise AnsibleError(str(e)) from e
        try:
            er = store.ensure(
                term,
                state="present",
                overwrite=False,
                check_mode=False,
                check_recipients=check_recipients,
            )
        except (ValueError, RuntimeError, FileNotFoundError) as e:
            raise AnsibleError(str(e)) from e

        return [er.secret] if er.secret is not None else []

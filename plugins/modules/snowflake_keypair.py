#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2026, iacforge contributors
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: snowflake_keypair
short_description: Generate an RSA key pair for Snowflake key-pair authentication
author:
  - iacforge contributors (@iacforge)
description:
  - Writes an (optionally encrypted) PKCS#8 private key and returns the public key body
    and its Snowflake-style fingerprint.
  - If the key file exists and O(force=false), the existing key is read and nothing changes.
options:
  path:
    description: Private key file to create.
    type: path
    required: true
  passphrase:
    description: Encrypts the private key (recommended).
    type: str
  size:
    description: RSA key size in bits.
    type: int
    choices: [2048, 3072, 4096]
    default: 2048
  force:
    description: Always generate a new key (rotation).
    type: bool
    default: false
  mode:
    description: File mode of the private key.
    type: raw
    default: "0600"
requirements:
  - cryptography >= 42
"""

EXAMPLES = r"""
- name: Key for the automation user
  iacforge.snowflake_iac.snowflake_keypair:
    path: "{{ playbook_dir }}/.keys/svc_platform_automation.p8"
    passphrase: "{{ vault_sf_new_key_passphrase }}"
  delegate_to: localhost
  register: keypair
"""

RETURN = r"""
public_key:
  description: Public key body (no PEM armour), ready for RSA_PUBLIC_KEY.
  returned: success
  type: str
public_key_pem:
  description: Public key in PEM format.
  returned: success
  type: str
fingerprint:
  description: SHA256 fingerprint as shown by Snowflake in RSA_PUBLIC_KEY_FP.
  returned: success
  type: str
path:
  description: Path of the private key file.
  returned: success
  type: str
"""

import base64
import hashlib
import os
import tempfile
import traceback

from ansible.module_utils.basic import AnsibleModule, missing_required_lib

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    HAS_CRYPTOGRAPHY = True
    IMPORT_ERROR = None
except ImportError:
    HAS_CRYPTOGRAPHY = False
    IMPORT_ERROR = traceback.format_exc()


def describe(key):
    der = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return dict(
        public_key=base64.b64encode(der).decode(),
        public_key_pem=pem.decode(),
        fingerprint="SHA256:" + base64.b64encode(hashlib.sha256(der).digest()).decode(),
    )


def main():
    module = AnsibleModule(
        argument_spec=dict(
            path=dict(type="path", required=True),
            passphrase=dict(type="str", no_log=True),
            size=dict(type="int", default=2048, choices=[2048, 3072, 4096]),
            force=dict(type="bool", default=False),
            mode=dict(type="raw", default="0600"),
        ),
        supports_check_mode=True,
    )
    if not HAS_CRYPTOGRAPHY:
        module.fail_json(msg=missing_required_lib("cryptography"), exception=IMPORT_ERROR)

    p = module.params
    path = p["path"]
    password = p["passphrase"].encode() if p["passphrase"] else None

    try:
        if os.path.exists(path) and not p["force"]:
            with open(path, "rb") as handle:
                key = serialization.load_pem_private_key(handle.read(), password=password)
            module.exit_json(changed=False, path=path, **describe(key))

        if module.check_mode:
            module.exit_json(changed=True, path=path)

        key = rsa.generate_private_key(public_exponent=65537, key_size=p["size"])
        encryption = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption)

        directory = os.path.dirname(path) or "."
        os.makedirs(directory, mode=0o700, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=directory)
        with os.fdopen(fd, "wb") as handle:
            handle.write(pem)
        module.atomic_move(tmp, path)
        module.set_mode_if_different(path, p["mode"], False)
        module.exit_json(changed=True, path=path, **describe(key))
    except (ValueError, TypeError) as exc:
        module.fail_json(msg="Cannot read private key (wrong passphrase?): %s" % exc)


if __name__ == "__main__":
    main()

# -*- coding: utf-8 -*-
# Copyright: (c) 2026, iacforge contributors
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)


class ModuleDocFragment(object):
    DOCUMENTATION = r"""
options:
  account:
    description: Snowflake account identifier, for example C(myorg-myaccount). Falls back to C(SF_ACCOUNT).
    type: str
    required: true
  user:
    description: Login name of the user to connect as. Falls back to C(SF_USER).
    type: str
    required: true
  private_key:
    description:
      - PEM private key content (key-pair authentication). Falls back to C(SF_PRIVATE_KEY).
      - Takes precedence over O(private_key_path).
    type: str
  private_key_path:
    description: Path to a PEM private key file on the managed node. Falls back to C(SF_PRIVATE_KEY_PATH).
    type: path
  private_key_passphrase:
    description: Passphrase of an encrypted private key. Falls back to C(SF_PRIVATE_KEY_PASSPHRASE).
    type: str
  role:
    description: Role used for the session. Falls back to C(SF_ROLE); otherwise the user's default role.
    type: str
  warehouse:
    description: Warehouse used for the session. Falls back to C(SF_WAREHOUSE).
    type: str
requirements:
  - snowflake-connector-python >= 3.10
  - cryptography >= 42
notes:
  - Password authentication is intentionally not supported.
"""

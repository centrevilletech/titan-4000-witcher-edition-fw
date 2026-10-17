"""Credential checks with no fleet credentials in source or generated artifacts."""
import json
import os
import re
from pathlib import Path

# Recognize an actual passwd record, not crypt library format strings.
ROOT_HASH = re.compile(rb'root:(\$(?:1|5|6|y)\$[^:\s\x00]+):0:0:root:([^:\s\x00]*):/bin/sh\n')
# Crypto libraries contain PEM delimiter strings. Require a body and matching
# end marker so we reject embedded keys without flagging format constants.
PRIVATE_KEY = re.compile(
    rb'-----BEGIN ((?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY)-----'
    rb'\r?\n[A-Za-z0-9+/=\r\n]{64,}-----END \1-----'
)


def legacy_credentials():
    """Optional local checks; mandatory in the official release workflow."""
    raw = os.environ.get('WITCHER_CREDENTIAL_DENYLIST_JSON', '')
    if not raw:
        if os.environ.get('WITCHER_REQUIRE_CREDENTIAL_DENYLIST') == '1':
            raise ValueError('Required credential audit secret is unavailable')
        return []
    try:
        values = json.loads(raw)
        if not isinstance(values, list) or not values or not all(isinstance(v, str) and len(v) >= 6 for v in values):
            raise ValueError()
        return [v.encode() for v in values]
    except (ValueError, TypeError):
        # Never include the environment value in an exception or CI output.
        raise ValueError('Credential audit secret must be a nonempty JSON string array') from None


def credential_findings(root, extra=()):
    """Inspect regular files only, never follow device nodes or image symlinks."""
    needles = [*legacy_credentials(), *extra]
    findings = []
    for path in Path(root).rglob('*'):
        if path.is_symlink() or not path.is_file():
            continue
        data = path.read_bytes()
        if ROOT_HASH.search(data) or PRIVATE_KEY.search(data) or any(n in data for n in needles):
            findings.append(str(path.relative_to(root)))
    return findings

#!/usr/bin/env python3
"""Record Witcher identity separately from the vendor base firmware version."""
import json,re,subprocess,sys
from pathlib import Path
repo=Path(__file__).resolve().parent.parent
version=(repo/'VERSION').read_text().strip()
if not re.fullmatch(r'(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?',version):
    sys.exit('Invalid VERSION')
root=Path(sys.argv[1])
try:
    commit=subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip()
    dirty=bool(subprocess.check_output(['git','-C',str(repo),'status','--porcelain'],text=True).strip())
except subprocess.CalledProcessError:
    commit='unknown';dirty=True
record={'name':'Witcher','version':version,'display':f'Witcher v{version}',
        'base_firmware':'V1.6.0.P0.4172','source_commit':commit,'dirty':dirty}
(root/'etc/witcher-release').write_text(json.dumps(record,sort_keys=True)+'\n')
(root/'etc/witcher-release').chmod(0o644)
print(record['display'],commit,'(modified working tree)' if dirty else '')

#!/usr/bin/env python3
"""Mutation regressions for the explicit operational authority contract."""
import shutil
import tempfile
from pathlib import Path
import md5_execution_policy as policy

def main():
    count=0
    with tempfile.TemporaryDirectory(prefix='brynja-md5-policy-') as temporary:
        root=Path(temporary)
        for name in policy.paths()+list(policy.GATES)+[policy.REVIEW]:
            dst=root/name; dst.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(policy.ROOT/name,dst)
        policy.validate(root)
        for name,lines in policy.GATES.items():
            path=root/name; original=path.read_text()
            for line in lines:
                path.write_text(original.replace(line,'# omitted gate'))
                try: policy.validate(root,reviewed=False)
                except ValueError: count+=1
                else: raise AssertionError('accepted removed verification gate')
                finally: path.write_text(original)
        for name,tokens in policy.CHECKS.items():
            path=root/name; original=path.read_text()
            # Work on whitespace-normalized content: checks deliberately permit
            # rustfmt but must reject each actual required expression removal.
            normalized=''.join(original.split())
            for token in tokens:
                token=''.join(token.split())
                if token not in normalized: raise AssertionError('missing mutation site')
                path.write_text(normalized.replace(token,'REMOVED'))
                try: policy.validate(root,reviewed=False)
                except ValueError: count+=1
                else: raise AssertionError('accepted removed authority/transaction expression: '+token)
                finally: path.write_text(original)
    print(f'MD5 operational authority/transaction policy: {count} mutations rejected')

if __name__=='__main__': main()

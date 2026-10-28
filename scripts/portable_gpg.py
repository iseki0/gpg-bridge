#!/usr/bin/env python3
"""TEST ONLY. PGPy-backed signing fixture for sandboxes without Unix sockets.
This is NOT a production GnuPG replacement and does not exercise gpg-agent.
All keys are disposable, unprotected test keys under the e2e temporary directory.
"""
import email.utils
from pathlib import Path
import sys
import time
import warnings
warnings.filterwarnings('ignore')
from pgpy import PGPKey, PGPUID
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm


def main():
    args = sys.argv[1:]
    home = Path(args[args.index('--homedir') + 1])
    files = sorted(home.glob('fixture-*.asc'))
    keys = [(p, PGPKey.from_blob(p.read_bytes())[0]) for p in files]
    if '--quick-generate-key' in args:
        at = args.index('--quick-generate-key')
        name, email_address = email.utils.parseaddr(args[at + 1])
        key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
        usage = KeyFlags.Certify if args[at + 3] == 'cert' else KeyFlags.Sign
        key.add_uid(PGPUID.new(name, email=email_address), usage={usage}, hashes=[HashAlgorithm.SHA256],
                    ciphers=[SymmetricKeyAlgorithm.AES256], compression=[CompressionAlgorithm.Uncompressed])
        (home / f'fixture-{len(keys)}.asc').write_text(str(key))
    elif '--quick-add-key' in args:
        primary = args[args.index('--quick-add-key') + 1]
        path, key = next((p, k) for p, k in keys if str(k.fingerprint) == primary)
        sub = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
        key.add_subkey(sub, usage={KeyFlags.Sign})
        path.write_text(str(key))
    elif '--list-secret-keys' in args:
        def record(kind, key, caps):
            fields = [''] * 16
            fields[0] = kind
            fields[1] = 'u'
            fields[5] = str(int(key.created.timestamp()))
            fields[6] = '0'
            fields[11] = caps
            fields[14] = '+'
            print(':'.join(fields))
            print('fpr:::::::::' + str(key.fingerprint) + ':')
        for _, key in keys:
            record('sec', key, 'cSC' if key.subkeys else 'scSC')
            print('uid:u::::::::' + str(next(iter(key.userids))) + ':')
            for sub in key.subkeys.values():
                record('ssb', sub, 's')
    elif '--export' in args:
        for _, key in keys:
            if str(key.fingerprint) in args:
                print(str(key.pubkey))
    elif '--detach-sign' in args:
        fingerprint = args[args.index('--local-user') + 1].rstrip('!')
        candidates = [candidate for _, key in keys for candidate in [key, *key.subkeys.values()]]
        key = next(k for k in candidates if str(k.fingerprint) == fingerprint)
        data = sys.stdin.buffer.read()
        signature = key.sign(data, detached=True, hash=HashAlgorithm.SHA256)
        print(str(signature))
        print(f'[GNUPG:] SIG_CREATED D 1 8 00 {int(time.time())} {fingerprint}', file=sys.stderr)
    else:
        raise SystemExit('unsupported test fixture invocation')


if __name__ == '__main__':
    main()

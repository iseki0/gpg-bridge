#!/usr/bin/env python3
"""Real GnuPG + Git integration tests. All keys/repos are disposable and isolated.
Run: python3 scripts/e2e.py --binary target/debug/gpg-bridge
"""
import argparse
import base64
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', default='target/debug/gpg-bridge')
    parser.add_argument('--portable-fixture', action='store_true', help='PGPy signing fixture + real GPG verification; does NOT test gpg-agent')
    args = parser.parse_args()
    binary = Path(args.binary).resolve()
    signer = Path(__file__).with_name('portable_gpg.py').resolve() if args.portable_fixture else Path(shutil.which('gpg')).resolve()
    env = os.environ.copy()
    env['NO_PROXY'] = env['no_proxy'] = '127.0.0.1,localhost'
    servers = []
    with tempfile.TemporaryDirectory(prefix='gpg bridge test ') as tmp:
        root = Path(tmp)
        home = root / 'secret-home'
        home.mkdir(mode=0o700)
        repo = root / "repo with 'quotes'"
        repo.mkdir()
        bindir = root / "bin with 'quotes'"
        bindir.mkdir()
        exe = bindir / 'gpg-bridge'
        shutil.copy2(binary, exe)
        exe.chmod(0o700)
        env['XDG_CONFIG_HOME'] = str(root / 'config')

        def run(*argv, cwd=repo, data=None, success=True):
            p = subprocess.run(list(map(str, argv)), cwd=cwd, env=env, input=data,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=35)
            if success and p.returncode:
                raise AssertionError(f'{argv[0:3]} failed ({p.returncode}): {p.stderr.decode(errors="replace")}')
            if not success:
                assert p.returncode != 0, f'Unexpected success: {argv[0:3]}'
            return p

        def gpg(*argv, **kw):
            passphrase = kw.pop('passphrase', '')
            return run(signer, '--homedir', home, '--batch', '--pinentry-mode', 'loopback', '--passphrase', passphrase, *argv, **kw)

        def fingerprints():
            text = gpg('--with-colons', '--list-secret-keys').stdout.decode()
            return [l.split(':')[9] for l in text.splitlines() if l.startswith('fpr:')]

        try:
            if args.portable_fixture:
                print('NOTE: portable PGPy fixture mode; gpg-agent is NOT exercised', flush=True)
            gpg('--quick-generate-key', 'Bridge Test <bridge@example.invalid>', 'ed25519', 'cert', '1d')
            primary = fingerprints()[0]
            gpg('--quick-add-key', primary, 'ed25519', 'sign', '1d')
            allowed = fingerprints()[1]
            gpg('--quick-generate-key', 'Other Test <other@example.invalid>', 'ed25519', 'sign', '1d')
            other = fingerprints()[-1]
            run('git', 'init', '-q')
            run('git', 'config', 'user.name', 'Bridge Test')
            run('git', 'config', 'user.email', 'bridge@example.invalid')
            run('git', 'config', 'commit.gpgsign', 'false')
            run('git', 'config', 'gpg.format', 'ssh')
            run('git', 'config', 'gpg.program', '/previous/gpg')
            def config_snapshot():
                result = {}
                for record in run('git', 'config', '--local', '--null', '--list').stdout.split(b'\0'):
                    if record:
                        key, _, value = record.partition(b'\n')
                        result.setdefault(key, []).append(value)
                return result

            old = config_snapshot()
            run('git', 'commit', '--allow-empty', '-qm', 'unsigned baseline')

            def start(auto=True, ttl=120, tailscale=False, signing_key=None, extra=()):
                with socket.socket() as sock:
                    sock.bind(('127.0.0.1', 0))
                    port = sock.getsockname()[1]
                logfile = root / f'server-{len(servers)}.log'
                log = logfile.open('wb')
                cmd = [exe, 'serve', '--bind', f'127.0.0.1:{port}', '--endpoint', f'http://127.0.0.1:{port}',
                       '--homedir', home, '--gpg', signer, '--key', signing_key or primary, '--ttl', str(ttl), *extra]
                if tailscale:
                    cmd.extend(['--tailscale-serve'])
                    at = cmd.index('--endpoint')
                    del cmd[at:at + 2]
                if auto:
                    cmd.append('--auto-approve')
                p = subprocess.Popen(list(map(str, cmd)), env=env, stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=log)
                servers.append((p, log))
                # A startup failure closes stdout; no credential is printed in test output.
                ticket = p.stdout.readline().decode().strip()
                assert ticket.startswith('gpgbridge:v1:'), logfile.read_text(errors='replace')
                return p, ticket, logfile

            server, ticket, log = start()
            run(exe, 'connect', data=(ticket + '\n').encode())
            cfg_path = repo / '.git/gpg-bridge-client.json'
            assert cfg_path.stat().st_mode & 0o777 == 0o600
            run(exe, 'status')
            run('git', 'commit', '--allow-empty', '-qm', 'signed through bridge')
            run('git', 'verify-commit', 'HEAD')
            verify = run('git', 'log', '-1', '--format=%GF').stdout.decode().strip()
            assert verify == allowed, (verify, allowed)
            run('git', 'tag', '-s', 'v-test', '-m', 'signed tag')
            run('git', 'verify-tag', 'v-test')
            public_home = repo / '.git/gpg-bridge-gnupg'
            if args.portable_fixture:
                packets = run('gpg', '--homedir', public_home, '--no-autostart', '--list-packets', public_home / 'pubring.gpg').stdout
                assert b':secret key packet:' not in packets and b':secret sub key packet:' not in packets
                assert not list((public_home / 'private-keys-v1.d').glob('*.key'))
            else:
                secrets = run('gpg', '--homedir', public_home, '--with-colons', '--list-secret-keys').stdout
                assert b'sec:' not in secrets and b'ssb:' not in secrets
            print('PASS: signed commit + tag verified by GnuPG, exact signing subkey, public-only verification home, quoted paths')

            before = run('git', 'rev-parse', 'HEAD').stdout
            run('git', 'config', 'user.signingkey', other + '!')
            run('git', 'commit', '--allow-empty', '-qm', 'must be rejected', success=False)
            assert run('git', 'rev-parse', 'HEAD').stdout == before
            run('git', 'config', 'user.signingkey', allowed + '!')
            print('PASS: unauthorized key rejected, no commit created')

            raw = cfg_path.read_bytes()
            config = json.loads(raw)
            config['ticket']['psk'] = base64.urlsafe_b64encode(bytes(32)).decode().rstrip('=')
            cfg_path.write_text(json.dumps(config))
            run(exe, 'status', success=False)
            cfg_path.write_bytes(raw)
            print('PASS: wrong pairing credential rejected')

            oversized = root / 'oversized-message.txt'
            oversized.write_bytes(b'x' * (1024 * 1024 + 1))
            before = run('git', 'rev-parse', 'HEAD').stdout
            run('git', 'commit', '--allow-empty', '-qF', oversized, success=False)
            assert run('git', 'rev-parse', 'HEAD').stdout == before
            print('PASS: oversized signing input rejected without creating a commit')

            server.terminate()
            server.wait(timeout=5)
            run('git', 'verify-commit', 'HEAD')
            run('git', 'verify-tag', 'v-test')
            run(exe, 'disconnect')
            assert config_snapshot() == old, (config_snapshot(), old)
            assert not cfg_path.exists()
            print('PASS: offline verification and exact restoration of prior Git configuration')

            server, ticket, log = start(auto=False)
            run(exe, 'connect', data=(ticket + '\n').encode())
            before = run('git', 'rev-parse', 'HEAD').stdout
            for answer, expected in [('n', False), ('y', True)]:
                previous_log_size = log.stat().st_size
                commit = subprocess.Popen(['git', 'commit', '--allow-empty', '-qm', f'confirm {answer}'],
                                          cwd=repo, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    if '允许此签名？' in log.read_bytes()[previous_log_size:].decode(errors='replace'):
                        break
                    if commit.poll() is not None:
                        raise AssertionError(commit.communicate()[1].decode(errors='replace'))
                    time.sleep(0.05)
                else:
                    commit.kill()
                    raise AssertionError('Confirmation prompt missing')
                server.stdin.write((answer + '\n').encode())
                server.stdin.flush()
                _, stderr = commit.communicate(timeout=20)
                assert (commit.returncode == 0) == expected, stderr.decode(errors='replace')
                if expected:
                    run('git', 'verify-commit', 'HEAD')
                else:
                    assert run('git', 'rev-parse', 'HEAD').stdout == before
            run(exe, 'disconnect')
            server.terminate()
            server.wait(timeout=5)
            print('PASS: real local confirmation denies N and permits Y')

            server, ticket, log = start(ttl=3)
            run(exe, 'connect', data=(ticket + '\n').encode())
            server.wait(timeout=10)
            run(exe, 'status', success=False)
            run('git', 'commit', '--allow-empty', '-qm', 'expired', success=False)
            run(exe, 'disconnect')
            print('PASS: expiry stops server, blocks signing, still permits disconnect')

            server, ticket, log = start()
            run(exe, 'connect', data=(ticket + '\n').encode())
            run('git', 'config', 'commit.gpgsign', 'false')
            run(exe, 'disconnect')
            assert run('git', 'config', 'commit.gpgsign').stdout.strip() == b'false'
            print('PASS: disconnect preserves Git settings modified after connect')

            # A local CLI stub exercises Serve without changing any tailnet.
            tailscale = bindir / 'tailscale'
            tailscale.write_text(
                '#!' + sys.executable + '\n'
                'import json, os, sys\n'
                'from pathlib import Path\n'
                'with Path(os.environ["TAILSCALE_TEST_CALLS"]).open("a") as f:\n'
                '    f.write(json.dumps(sys.argv[1:]) + "\\n")\n'
                'if sys.argv[1:] == ["status", "--json"]:\n'
                '    print(json.dumps({"Self": {"DNSName": "test.tailnet.ts.net."}}))\n'
                'else:\n'
                '    print("Tailscale informational output")\n'
                '    sys.exit(int(os.environ.get("TAILSCALE_TEST_FAIL", "0")))\n'
            )
            tailscale.chmod(0o700)
            calls = root / 'tailscale-calls.jsonl'
            env['PATH'] = str(bindir) + os.pathsep + env['PATH']
            env['TAILSCALE_TEST_CALLS'] = str(calls)
            server, ticket, log = start(tailscale=True)
            payload = ticket.removeprefix('gpgbridge:v1:')
            decoded = json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))
            assert decoded['endpoint'] == 'https://test.tailnet.ts.net'
            invoked = [json.loads(line) for line in calls.read_text().splitlines()]
            assert invoked[0][:2] == ['serve', '--bg']
            assert invoked[0][2].startswith('http://127.0.0.1:')
            assert invoked[1] == ['status', '--json']
            assert 'Tailscale informational output' in log.read_text()
            server.terminate()
            server.wait(timeout=5)
            env['TAILSCALE_TEST_FAIL'] = '1'
            result = run(exe, 'serve', '--tailscale-serve', '--homedir', home,
                         '--gpg', signer, '--key', primary, success=False)
            assert not result.stdout
            assert 'Tailscale Serve 启动失败' in result.stderr.decode()
            for bind in ['0.0.0.0:17389', '127.0.0.1:0']:
                result = run(exe, 'serve', '--tailscale-serve', '--bind', bind, success=False)
                assert not result.stdout
                assert '--tailscale-serve 需要' in result.stderr.decode()
            print('PASS: automatic Tailscale Serve, HTTPS discovery, clean ticket output, failure and invalid bind rejection (CLI stub)')

            if not args.portable_fixture:
                secret = 'test-only passphrase with spaces & quotes\''
                gpg('--quick-generate-key', 'Protected Test <protected@example.invalid>',
                    'ed25519', 'sign', '1d', passphrase=secret)
                protected = fingerprints()[-1]
                # Disable real Pinentry; clear the agent cache before each run.
                (home / 'gpg-agent.conf').write_text(
                    'allow-loopback-pinentry\npinentry-program /nonexistent-test-pinentry\n'
                )
                def clear_agent():
                    run('gpgconf', '--homedir', home, '--kill', 'gpg-agent')

                clear_agent()
                server, ticket, log = start(signing_key=protected,
                    extra=['--gpg-passphrase', 'wrong-test-passphrase'])
                run(exe, 'connect', data=(ticket + '\n').encode())
                before = run('git', 'rev-parse', 'HEAD').stdout
                run('git', 'commit', '--allow-empty', '-qm', 'wrong passphrase', success=False)
                assert run('git', 'rev-parse', 'HEAD').stdout == before
                run(exe, 'disconnect')
                server.terminate()
                server.wait(timeout=5)
                passfile = root / 'passphrase with spaces.txt'
                passfile.write_text(secret + '\r\n')
                passfile.chmod(0o600)
                for extra in [['--gpg-passphrase', secret], ['--gpg-passphrase-file', passfile]]:
                    clear_agent()
                    server, ticket, log = start(signing_key=protected, extra=extra)
                    run(exe, 'connect', data=(ticket + '\n').encode())
                    run('git', 'config', 'commit.gpgsign', 'true')
                    run('git', 'commit', '--allow-empty', '-qm', 'protected signing without Pinentry')
                    run('git', 'verify-commit', 'HEAD')
                    actual = run('git', 'log', '-1', '--format=%GF').stdout.decode().strip()
                    assert actual == protected
                    assert secret not in cfg_path.read_text()
                    assert secret not in log.read_text()
                    run(exe, 'disconnect')
                    server.terminate()
                    server.wait(timeout=5)
                result = run(exe, 'serve', '--gpg-passphrase', 'bad\nsecond-line', success=False)
                assert not result.stdout and '口令不能包含' in result.stderr.decode()
                result = run(exe, 'serve', '--gpg-passphrase', secret,
                             '--gpg-passphrase-file', passfile, success=False)
                assert not result.stdout
                print('PASS: protected-key signing with direct/file passphrase, cold agent, no Pinentry, wrong password rejection, no credential/log leak')

            # Credential output must not leak into the separately captured server audit.
            all_logs = ''.join(p.read_text(errors='replace') for p in root.glob('server-*.log'))
            assert 'gpgbridge:v1:' not in all_logs
            assert '签名成功' in all_logs and '作者=' in all_logs
            print('PASS: action audit includes signing metadata and excludes pairing strings')
        finally:
            for p, log in servers:
                if p.poll() is None:
                    p.terminate()
                    try:
                        p.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        p.kill()
                        p.wait()
                log.close()
            subprocess.run(['gpgconf', '--homedir', str(home), '--kill', 'all'], env=env,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)


if __name__ == '__main__':
    main()

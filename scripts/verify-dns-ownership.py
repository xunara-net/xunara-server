import argparse
import http.cookiejar
import json
import os
import re
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


def unused_port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


def wait_ready(predicate):
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        try:
            if predicate():
                return
        except (OSError, ValueError, urllib.error.URLError, subprocess.SubprocessError):
            pass
        time.sleep(0.2)
    raise RuntimeError('isolated fixture readiness failed')


def stop_process(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)


def main():
    parser = argparse.ArgumentParser(description='Isolated official Linux client DNS name ownership smoke test')
    parser.add_argument('--server-binary', required=True, type=Path)
    parser.add_argument('--relay-binary', required=True, type=Path)
    parser.add_argument('--tailscale', default='/usr/bin/tailscale')
    parser.add_argument('--tailscaled', default='/usr/sbin/tailscaled')
    args = parser.parse_args()
    server_binary, relay_binary = str(args.server_binary.resolve()), str(args.relay_binary.resolve())
    client_version = subprocess.check_output([args.tailscale, 'version']).decode().splitlines()[0]
    processes = []
    domain = 'official.xunara.test'
    with tempfile.TemporaryDirectory(prefix='xunara-official-dns-') as directory:
        root = Path(directory)
        root.chmod(0o700)
        try:
            origin = 'http://127.0.0.1:' + str(unused_port())
            state = root / 'control'
            platform_token = secrets.token_urlsafe(32)
            opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
            csrf = ''

            def call(endpoint, body=None, method='GET', platform=False):
                headers = {'Content-Type': 'application/json'}
                if platform:
                    headers['Authorization'] = 'Bearer ' + platform_token
                elif method != 'GET' and csrf:
                    headers['X-CSRF-Token'] = csrf
                request = urllib.request.Request(origin + endpoint,
                    data=None if body is None else json.dumps(body).encode(), method=method, headers=headers)
                with opener.open(request, timeout=10) as response:
                    return json.load(response)

            def launch(command, environment=None):
                process = subprocess.Popen(command, env=environment, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
                processes.append(process)
                return process

            relay_map = root / 'derp.json'
            relay = launch([relay_binary, '-listen', '127.0.0.1:' + str(unused_port()),
                '-hostname', '127.0.0.1', '-state-dir', str(root / 'relay'), '-cert-mode', 'selfsigned',
                '-stun-port', str(unused_port()), '-region-id', '991', '-derp-map-out', str(relay_map),
                '-log-level', 'error'])
            wait_ready(lambda: relay_map.exists() and relay.poll() is None)
            server_command = [server_binary, '-listen', urllib.parse.urlsplit(origin).netloc,
                '-grpc-listen', '127.0.0.1:0', '-server-url', origin, '-state-dir', str(state),
                '-domain', domain, '-plans', 'builtin', '-network-pool', '100.100.0.0/16',
                '-derp-map', str(relay_map), '-log-level', 'error']
            environment = dict(os.environ, XUNARA_PLATFORM_ADMIN_TOKEN=platform_token)
            daemon = launch(server_command, environment)
            wait_ready(lambda: call('/health').get('status') == 'pass')
            markup = opener.open(origin + '/setup', timeout=10).read().decode()
            password = secrets.token_urlsafe(24)
            form = {'token': (state / 'setup-token').read_text().strip(),
                '_csrf': re.search(r'name="_csrf" value="([^"]+)"', markup).group(1),
                'login': 'dns-owner', 'password': password, 'confirm': password}
            request = urllib.request.Request(origin + '/setup', data=urllib.parse.urlencode(form).encode(),
                headers={'Content-Type': 'application/x-www-form-urlencoded'})
            with opener.open(request, timeout=10) as response:
                if response.status != 200:
                    raise RuntimeError('isolated owner setup failed')
            call('/api/platform/v1/organizations/default/plan', {'plan_id': 'pro'}, 'PATCH', True)
            csrf = call('/api/v2/network/addresses')['csrf_token']
            for name, address in [('official-client', '100.64.0.99'), ('database', '100.64.0.98')]:
                call('/api/v2/dns/records', {'name': name + '.' + domain, 'type': 'A', 'value': address}, 'POST')
            auth_key = call('/api/v1/auth-keys', {'ttl': '1h', 'reusable': True}, 'POST')['key']
            key_file = root / 'auth-key'
            descriptor = os.open(str(key_file), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'w') as stream:
                stream.write(auth_key)

            clients = []
            for index in range(2):
                client_root = root / ('client-' + str(index))
                client_root.mkdir(mode=0o700)
                socket_path = client_root / 'tailscaled.sock'
                client = launch([args.tailscaled, '--tun=userspace-networking', '--socket=' + str(socket_path),
                    '--state=' + str(client_root / 'state'), '--port=0', '--no-logs-no-support'])
                wait_ready(lambda: socket_path.exists() and client.poll() is None)
                command = [args.tailscale, '--socket=' + str(socket_path)]
                result = subprocess.run(command + ['up', '--login-server=' + origin,
                    '--auth-key=file:' + str(key_file), '--hostname=official-client',
                    '--accept-dns=false', '--accept-routes=false'], stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, timeout=45)
                if result.returncode != 0:
                    raise RuntimeError('official client registration failed')

                def status(command=command):
                    return json.loads(subprocess.check_output(command + ['status', '--json'], timeout=10))

                wait_ready(lambda: status().get('BackendState') == 'Running')
                self_node = status()['Self']
                ipv4 = next(address for address in self_node['TailscaleIPs'] if ':' not in address)
                clients.append({'command': command, 'status': status, 'ipv4': ipv4, 'name': self_node['DNSName']})
            if clients[0]['name'] == clients[1]['name'] or any(client['name'] == 'official-client.' + domain + '.' for client in clients):
                raise RuntimeError('registered devices shadowed reserved DNS names')

            def query(client, name, record_type='A'):
                result = subprocess.run(client['command'] + ['dns', 'query', '--json', name, record_type],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
                if result.returncode != 0:
                    raise RuntimeError('official internal DNS query failed')
                response = json.loads(result.stdout)
                if response['ResponseCode'] != 'RCodeSuccess':
                    return []
                return [answer['Body'] for answer in response.get('Answers', [])]

            wait_ready(lambda: clients[1]['ipv4'] in query(clients[0], clients[1]['name']))
            if query(clients[0], 'official-client.' + domain) != ['100.64.0.99']:
                raise RuntimeError('reserved custom record was overwritten')
            original_addresses = [client['ipv4'] for client in clients]
            subprocess.check_call(clients[0]['command'] + ['set', '--hostname=database'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
            wait_ready(lambda: clients[0]['status']()['Self']['DNSName'].startswith('database-'))
            renamed = clients[0]['status']()['Self']['DNSName']
            wait_ready(lambda: clients[0]['ipv4'] in query(clients[1], renamed))
            if query(clients[1], 'database.' + domain) != ['100.64.0.98']:
                raise RuntimeError('rename shadowed reserved DNS record')
            if clients[0]['ipv4'] not in clients[0]['status']()['Self']['TailscaleIPs']:
                raise RuntimeError('rename changed device addresses')
            # 实际通过官方内部 DNS 查询，不把 CLI 自身的 peer 名匹配当作解析验收。
            reverse_name = '.'.join(reversed(clients[0]['ipv4'].split('.'))) + '.in-addr.arpa'
            if renamed not in query(clients[1], reverse_name, 'PTR'):
                raise RuntimeError('PTR did not follow assigned device name')
            result = subprocess.run(clients[1]['command'] + ['ping', '--icmp', '--c=1', '--timeout=8s', renamed],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
            if result.returncode != 0:
                raise RuntimeError('WireGuard ICMP failed after device rename')
            try:
                call('/api/v2/dns/records', {'name': renamed, 'type': 'A', 'value': '100.64.0.97'}, 'POST')
            except urllib.error.HTTPError as error:
                if error.code != 403:
                    raise RuntimeError('assigned alias protection returned an unexpected status') from None
            else:
                raise RuntimeError('administrator record shadowed assigned device alias')
            stop_process(daemon)
            daemon = launch(server_command, environment)
            wait_ready(lambda: call('/health').get('status') == 'pass')
            wait_ready(lambda: clients[0]['ipv4'] in query(clients[1], renamed))
            machines = call('/api/v1/machines')['machines']
            if sorted(machine['ipv4'] for machine in machines) != sorted(original_addresses):
                raise RuntimeError('restart changed device allocation')
            expected_names = sorted([renamed.rstrip('.'), clients[1]['name'].rstrip('.')])
            if sorted(machine['dnsName'].rstrip('.') for machine in machines) != expected_names:
                raise RuntimeError('restart lost persisted allocated DNS names')
            print(json.dumps({'passed': True, 'client_version': client_version,
                'mode': 'isolated Linux userspace-networking; no host DNS changes', 'production_writes': False,
                'same_hostname_registration': True, 'custom_record_preserved': True,
                'live_rename_alias': True, 'internal_A_and_PTR_queries': True, 'alias_API_protection': True,
                'wireguard_ICMP_after_rename': True, 'restart_preserves_addresses_and_names': True,
                'all_OS_or_host_resolver_verified': False}))
        finally:
            for process in reversed(processes):
                stop_process(process)


if __name__ == '__main__':
    main()

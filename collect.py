"""Collect public URI subscriptions; stdlib only. Does not test VPN connectivity."""
import base64
import concurrent.futures
import hashlib
import json
import re
import time
import urllib.parse as url
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
NAME = '@vpn_fortuna'
ALIASES = {'hy2': 'hysteria2', 'hysteria2': 'hysteria2', 'hysteria': 'hysteria',
           'vless': 'vless', 'vmess': 'vmess', 'trojan': 'trojan', 'tuic': 'tuic', 'ss': 'ss'}
URI = re.compile(r'(?:vless|vmess|trojan|hysteria2?|hy2|tuic|ss)://[^\s<>"\x27]+', re.I)


def decode(value):
    value = re.sub(r'\s+', '', value)
    return base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True).decode('utf-8-sig')


def encode(value):
    return base64.b64encode(value.encode()).decode()


def extract(text):
    links = URI.findall(text)
    if not links:
        try:
            links = URI.findall(decode(text))
        except (ValueError, UnicodeError):
            pass
    return links


def bucket(value, fallback):
    value = str(value).lower()
    return value if re.fullmatch(r'[a-z0-9_-]{1,32}', value) else fallback


def normalize(link):
    scheme = link.split('://', 1)[0].lower()
    protocol = ALIASES[scheme]
    if protocol == 'vmess':
        obj = json.loads(decode(link.split('://', 1)[1].split('#', 1)[0]))
        if not all(obj.get(k) for k in ('add', 'port', 'id')):
            raise ValueError('Incomplete VMess')
        if not 0 < int(obj['port']) < 65536:
            raise ValueError('Invalid port')
        obj['add'] = str(obj['add']).lower()
        obj['port'] = str(obj['port'])
        obj.pop('ps', None)
        key = 'vmess://' + json.dumps(obj, sort_keys=True, separators=(',', ':'))
        transport = bucket(obj.get('net', 'tcp'), 'unknown')
        security = bucket(obj.get('tls') or 'none', 'unknown')
        obj['ps'] = NAME
        return key, 'vmess://' + encode(json.dumps(obj, ensure_ascii=False, separators=(',', ':'))), protocol, transport, security
    parsed = url.urlsplit(link)
    # Legacy Shadowsocks encodes the entire userinfo@host:port part.
    if protocol == 'ss' and '@' not in parsed.netloc:
        parsed = url.urlsplit('ss://' + decode(parsed.netloc) + ('?' + parsed.query if parsed.query else ''))
    if not parsed.hostname or not parsed.port or not 0 < parsed.port < 65536:
        raise ValueError('Missing host or port')
    if protocol in ('vless', 'trojan', 'tuic', 'ss') and parsed.username is None:
        raise ValueError('Missing credentials')
    pairs = url.parse_qsl(parsed.query, keep_blank_values=True)
    params = dict(pairs)
    host = parsed.hostname.lower()
    host = '[' + host + ']' if ':' in host else host
    auth = parsed.netloc.rsplit('@', 1)[0] if '@' in parsed.netloc else ''
    if protocol == 'ss' and auth and ':' not in auth:
        auth = decode(url.unquote(auth))
    # Normalize encoding for comparison, but preserve original URI credentials in output.
    canonical_auth = url.unquote(auth)
    key = json.dumps([protocol, canonical_auth, host, parsed.port, parsed.path,
                      sorted(pairs)], separators=(',', ':'), ensure_ascii=False)
    output = link.split('#', 1)[0] + '#' + url.quote(NAME, safe='')
    transport = bucket(params.get('type') or params.get('network') or
                       ('quic' if protocol in ('hysteria', 'hysteria2', 'tuic') else 'tcp'), 'unknown')
    security = bucket(params.get('security') or ('tls' if protocol in ('trojan', 'hysteria', 'hysteria2', 'tuic') else 'none'), 'unknown')
    return key, output, protocol, transport, security


def fetch(source):
    for attempt in range(3):
        try:
            req = urllib.request.Request(source, headers={'User-Agent': 'vpn-fortuna-subscription/1.0'})
            with urllib.request.urlopen(req, timeout=45) as response:
                data = response.read(32 * 1024 * 1024 + 1)
                if len(data) > 32 * 1024 * 1024:
                    raise ValueError('Source exceeds 32 MiB')
            links = extract(data.decode('utf-8-sig'))
            valid = []
            for link in links:
                try:
                    normalize(link)
                    valid.append(link)
                except (ValueError, KeyError, TypeError, UnicodeError):
                    pass
            if not valid:
                raise ValueError('No supported valid URI entries')
            return source, valid, None, len(links) - len(valid)
        except Exception as exc:
            error = type(exc).__name__ + ': ' + str(exc)
            if attempt < 2:
                time.sleep(2 ** attempt)
    return source, [], error, 0


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + '.tmp')
    temp.write_text(text, encoding='utf-8', newline='\n')
    temp.replace(path)


def main():
    sources = list(dict.fromkeys(line.strip() for line in (ROOT / 'sources.txt').read_text().splitlines()
                                if line.strip() and not line.lstrip().startswith('#')))
    cache = ROOT / '.source-cache'
    unique, reports = {}, []
    total, fresh = 0, 0
    now = datetime.now(timezone.utc).isoformat()
    with concurrent.futures.ThreadPoolExecutor(max_workers=7) as pool:
        for source, links, error, rejected in pool.map(fetch, sources):
            path = cache / (hashlib.sha256(source.encode()).hexdigest() + '.json')
            updated = now
            if error:
                if path.exists():
                    saved = json.loads(path.read_text(encoding='utf-8'))
                    links, updated = saved['links'], saved['updated']
                else:
                    updated = None
            else:
                fresh += 1
                write(path, json.dumps({'updated': now, 'links': links}, ensure_ascii=False))
            reports.append({'url': source, 'count': len(links), 'rejected': rejected,
                            'status': 'cached' if error and links else 'error' if error else 'ok',
                            'last_success': updated, 'error': error})
            print(f"{reports[-1]['status']}: {source}: {len(links)} entries", flush=True)
            for link in links:
                try:
                    key, *entry = normalize(link)
                except (ValueError, KeyError, TypeError, UnicodeError):
                    continue
                total += 1
                unique.setdefault(key, entry)
    if not fresh or not unique:
        raise SystemExit('No fresh usable sources; existing output preserved.')
    groups = defaultdict(list)
    for key in sorted(unique):
        link, protocol, transport, security = unique[key]
        for group in ('all', f'protocols/{protocol}', f'transports/{transport}',
                      f'security/{security}', f'combined/{protocol}/{transport}/{security}'):
            groups[group].append(link)
    output = ROOT / 'subscriptions'
    expected = set()
    for group, links in sorted(groups.items()):
        content = '\n'.join(links) + '\n'
        for suffix, value in (('.txt', content), ('.base64.txt', encode(content) + '\n')):
            path = output / (group + suffix)
            write(path, value)
            expected.add(path)
    for path in output.rglob('*.txt'):
        if path not in expected:
            path.unlink()
    stats = {'updated_utc': now, 'unique': len(unique), 'input_entries': total,
             'duplicates_removed': total - len(unique), 'sources': reports,
             'files': {k + '.txt': len(v) for k, v in sorted(groups.items())}}
    write(output / 'stats.json', json.dumps(stats, indent=2, ensure_ascii=False) + '\n')
    print(f'Unique: {len(unique)}; duplicates removed: {total-len(unique)}')


if __name__ == '__main__':
    main()

"""Collect public URI subscriptions; stdlib only. Does not test VPN connectivity."""
import base64
import concurrent.futures
import hashlib
import ipaddress
import json
import re
import time
import urllib.parse as url
import urllib.request
import uuid
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
    canonical_pairs = sorted(pairs) if len({k for k, _ in pairs}) == len(pairs) else pairs
    key = json.dumps([protocol, canonical_auth, host, parsed.port, parsed.path,
                      canonical_pairs], separators=(',', ':'), ensure_ascii=False)
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


def server_identity(key):
    """Literal IP deduplication; domain names are not resolved through DNS."""
    if key.startswith('vmess://'):
        host = json.loads(key[8:])['add']
    else:
        host = json.loads(key)[2]
    host = host.strip('[]').rstrip('.').lower()
    try:
        address = ipaddress.ip_address(host)
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        return 'ip:' + str(address)
    except ValueError:
        return 'domain:' + host.encode('idna').decode('ascii')


def deduplicate_servers(entries):
    seen, result = set(), {}
    for key, entry in entries.items():
        identity = server_identity(key)
        if identity not in seen:
            seen.add(identity)
            result[key] = entry
    return result


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + '.tmp')
    temp.write_text(text, encoding='utf-8', newline='\n')
    temp.replace(path)


def mobile_sample(links, limit=100):
    """Small diagnostic subscription; selection does not imply working endpoints."""
    result = []
    for link in links:
        try:
            parsed = url.urlsplit(link)
            uuid.UUID(url.unquote(parsed.username or ''))
            params = dict(url.parse_qsl(parsed.query))
            if params.get('type', 'tcp') not in ('tcp', 'ws', 'grpc'):
                continue
            if params.get('security', 'none') not in ('none', 'tls', 'reality'):
                continue
            if not parsed.query:
                link = link.split('#', 1)[0] + '?encryption=none#' + url.quote(NAME, safe='')
            result.append(link)
            if len(result) == limit:
                break
        except ValueError:
            continue
    return result


def nekobox_groups(links):
    result = []
    for link in links:
        key, _, protocol, _, _ = normalize(link)
        suffix = hashlib.sha256(key.encode()).hexdigest()[:16]
        name = f'{NAME} | {protocol.upper()} | {suffix}'
        if protocol == 'vmess':
            obj = json.loads(decode(link[8:]))
            obj['ps'] = name
            link = 'vmess://' + encode(json.dumps(obj, ensure_ascii=False, separators=(',', ':')))
        else:
            link = link.split('#', 1)[0] + '#' + url.quote(name, safe='')
        result.append(link)
    groups = {'nekobox/all': result}
    for offset in range(0, len(result), 500):
        groups[f'nekobox/part-{offset // 500 + 1:03d}'] = result[offset:offset + 500]
    return groups


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
    for key in sorted(unique, key=lambda k: (unique[k][1], k)):
        link, protocol, transport, security = unique[key]
        for group in ('all', f'protocols/{protocol}', f'transports/{transport}',
                      f'security/{security}', f'combined/{protocol}/{transport}/{security}'):
            groups[group].append(link)
    sample = mobile_sample(groups.get('protocols/vless', []))
    if sample:
        groups['v2rayng-test'] = sample
    named = nekobox_groups(groups['all'])
    for link in named['nekobox/all']:
        protocol = ALIASES[link.split('://', 1)[0].lower()]
        groups[f'v2rayng/{protocol}'].append(link)
    groups.update(named)
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
             'ip_or_domain_duplicates_removed': 0,
             'deduplication': 'connection parameters only; names ignored; different credentials, ports and transports retained',
             'duplicates_removed': total - len(unique), 'sources': reports,
             'files': {k + '.txt': len(v) for k, v in sorted(groups.items())}}
    write(output / 'stats.json', json.dumps(stats, indent=2, ensure_ascii=False) + '\n')
    print(f'Unique: {len(unique)}; duplicates removed: {total-len(unique)}')


if __name__ == '__main__':
    main()

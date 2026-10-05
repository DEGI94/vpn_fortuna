"""Verify published client feeds before committing them."""
import base64
import json
from pathlib import Path
from urllib.parse import urlsplit, unquote
from collect import normalize, decode

root = Path(__file__).resolve().parent / 'subscriptions'
for protocol in ('vless', 'vmess', 'trojan', 'ss', 'hysteria2'):
    text = (root / 'v2rayng' / (protocol + '.txt')).read_text(encoding='utf-8')
    encoded = (root / 'v2rayng' / (protocol + '.base64.txt')).read_text()
    assert base64.b64decode(encoded).decode() == text
    keys, names = set(), set()
    for link in text.splitlines():
        key, _, parsed_protocol, _, _ = normalize(link)
        assert parsed_protocol == protocol
        assert key not in keys
        keys.add(key)
        name = json.loads(decode(link[8:]))['ps'] if protocol == 'vmess' else unquote(urlsplit(link).fragment)
        assert name.startswith('@vpn_fortuna') and name not in names
        names.add(name)
    assert keys
    print(protocol, len(keys), 'unique connections verified')
stats = json.loads((root / 'stats.json').read_text(encoding='utf-8'))
assert stats['ip_or_domain_duplicates_removed'] == 0

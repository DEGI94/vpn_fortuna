import json
import unittest
from collect import normalize, encode, decode, extract, mobile_sample, deduplicate_servers, server_identity
from collect import nekobox_groups


class ParserTests(unittest.TestCase):
    def test_nekobox_unique_names_and_unchanged_connections(self):
        from urllib.parse import urlsplit, unquote
        links = [f'vless://abc@192.0.2.1:{port}?type=ws#same' for port in range(1000, 1501)]
        links.append('vmess://' + encode(json.dumps(dict(add='example.com', port=443, id='abc', ps='same'))))
        groups = nekobox_groups(links)
        names = []
        for before, after in zip(links, groups['nekobox/all']):
            self.assertEqual(normalize(before)[0], normalize(after)[0])
            names.append(json.loads(decode(after[8:]))['ps'] if after.startswith('vmess://') else unquote(urlsplit(after).fragment))
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(len(groups['nekobox/part-001']), 500)
        self.assertEqual(len(groups['nekobox/part-002']), 2)

    def test_cross_protocol_ip_dedup(self):
        links = ['vless://abc@1.2.3.4:443?type=ws', 'trojan://secret@1.2.3.4:8443',
                 'trojan://secret@1.2.3.5:443']
        entries = {item[0]: item[1:] for item in map(normalize, links)}
        result = deduplicate_servers(entries)
        self.assertEqual(len(result), 2)
        self.assertEqual(next(iter(result.values()))[1], 'vless')

    def test_ip_and_domain_normalization(self):
        def identity(host):
            return server_identity(normalize('trojan://x@' + host + ':443')[0])
        self.assertEqual(identity('[::ffff:1.2.3.4]'), identity('1.2.3.4'))
        self.assertEqual(identity('[2001:db8::1]'), identity('[2001:0db8:0:0:0:0:0:1]'))
        self.assertEqual(identity('EXAMPLE.com.'), identity('example.com'))
        vmess = 'vmess://' + encode(json.dumps(dict(add='1.2.3.4', port=443, id='abc')))
        self.assertEqual(server_identity(normalize(vmess)[0]), identity('1.2.3.4'))

    def test_mobile_sample(self):
        prefix = 'vless://00000000-0000-4000-8000-000000000001@example.com:443'
        result = mobile_sample(['vless://invalid@example.com:443', prefix + '#x',
                                prefix + '?type=xhttp#x'], limit=100)
        self.assertEqual(len(result), 1)
        self.assertIn('?encryption=none#%40vpn_fortuna', result[0])

    def test_names_and_parameter_order(self):
        a = normalize('vless://abc@EXAMPLE.com:443?security=reality&type=ws#old')
        b = normalize('vless://abc@example.com:443?type=ws&security=reality#new')
        self.assertEqual(a[0], b[0])
        self.assertTrue(a[1].endswith('#%40vpn_fortuna'))
        self.assertEqual(a[2:], ('vless', 'ws', 'reality'))

    def test_distinct_connection_parameters(self):
        prefix = 'vless://abc@example.com:443?'
        for left, right in [('path=/a', 'path=/b'), ('sni=a', 'sni=b'), ('pbk=a', 'pbk=b')]:
            self.assertNotEqual(normalize(prefix + left)[0], normalize(prefix + right)[0])

    def test_vmess(self):
        obj = dict(add='example.com', port=443, id='abc', ps='old', net='grpc', tls='tls')
        a = normalize('vmess://' + encode(json.dumps(obj)))
        obj['ps'] = 'other'
        self.assertEqual(a[0], normalize('vmess://' + encode(json.dumps(obj)))[0])
        self.assertEqual(json.loads(decode(a[1][8:]))['ps'], '@vpn_fortuna')
        self.assertEqual(a[2:], ('vmess', 'grpc', 'tls'))

    def test_base64_subscription(self):
        line = 'trojan://secret@example.com:443#old'
        self.assertEqual(extract(encode(line)), [line])

    def test_hysteria_alias(self):
        self.assertEqual(normalize('hy2://secret@example.com:443')[0],
                         normalize('hysteria2://secret@example.com:443')[0])

    def test_ss_formats(self):
        credentials = 'aes-256-gcm:secret'
        a = normalize('ss://' + encode(credentials) + '@example.com:443#x')
        b = normalize('ss://' + encode(credentials + '@example.com:443') + '#y')
        self.assertEqual(a[0], b[0])

    def test_invalid(self):
        for link in ['vless://abc@host:99999', 'trojan://host:443', 'vmess://garbage']:
            with self.assertRaises(ValueError):
                normalize(link)


if __name__ == '__main__':
    unittest.main()

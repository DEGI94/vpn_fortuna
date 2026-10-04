import json
import unittest
from collect import normalize, encode, decode, extract, mobile_sample


class ParserTests(unittest.TestCase):
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

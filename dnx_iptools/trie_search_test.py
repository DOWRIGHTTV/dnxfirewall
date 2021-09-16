import dnx_signature_operations
import trie_extension

import time

from ipaddress import IPv4Address

f_time = time.perf_counter_ns

sigs = dnx_signature_operations.generate_reputation(None)

t_ext = trie_extension.TrieRecurvSearch()

t_ext.generate_trie_structure(sigs)

del sigs

results = []

MSB = 0b11111111111110000000000000000000
LSB = 0b00000000000001111111111111111111

for ip in ['8.8.8.8', '69.69.69.69', '1.119.163.106', '1.1.1.1']:

    ip_addr = int(IPv4Address(ip))

    o = ip_addr & MSB
    t = ip_addr & LSB

    host = (o, t)

    start = f_time()
    result = t_ext.trie_search(host)

    total_time = f_time() - start

    results.append((f'{total_time} ns', f'rep={result}', f'MSB={o}', f'LSB={t}'))

print(results)
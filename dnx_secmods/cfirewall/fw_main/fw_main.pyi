from array import array


def nl_open() -> int: ...
def nl_bind() -> int: ...
def nl_break() -> int: ...
def initialize_geolocation(hash_trie: list, msb: int, lsb: int) -> int: ...


class CFirewall:

    def set_options(self, bypass: int, verbose: int) -> None: ...
    def nf_run(self) -> None: ...
    def nf_set(self, queue_num: int, queue_type: int) -> int: ...
    def update_rules(s, table_type: int, table_idx: int, ruleset: list) -> int: ...
    def update_zones(self, zone_map: array) -> int: ...
    # def update_ruleset(self, ruleset: int, rulelist: list) -> int: ...
    def remove_blockedlist(self, host_ip: int) -> int: ...

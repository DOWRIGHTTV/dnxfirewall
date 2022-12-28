class HashTrie_Range:
    def py_search(self, host: tuple[int, int]) -> int:
        '''C function wrapper to search the trie using a calculated hash.

        releases GIL prior to the call to search.
        '''
        ...
    def generate_structure(self, py_trie: list, py_trie_len: int) -> None: ...
    def search(self, trie_key: int, host_id: int) -> int:
        '''Search the trie using a calculated hash.

        C function and not accessible from python.
        '''
        ...

class HashTrie_Value:
    def py_search(self, trie_key: int) -> int:
        '''C function wrapper to search the trie using a calculated hash.

        releases GIL prior to the call to search.
        '''
        ...
    def generate_structure(self, py_trie: list, py_trie_len: int) -> None: ...
    def search(self, trie_key: int) -> int:
        '''Search the trie using a calculated hash.

        C function and not accessible from python.
        '''
        ...

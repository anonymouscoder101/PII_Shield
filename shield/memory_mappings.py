"""Versioned request-local mapping view; all mutations share the allocator lock."""

from collections.abc import Iterator, MutableMapping
from threading import RLock

from shield.contracts import TokenMapping


class MemoryMappings(MutableMapping[str, TokenMapping]):
    def __init__(self, lock: RLock):
        self._lock = lock
        self._data: dict[str, TokenMapping] = {}
        self.version = 0

    def __getitem__(self, token: str) -> TokenMapping:
        with self._lock:
            return self._data[token]

    def __setitem__(self, token: str, mapping: TokenMapping) -> None:
        with self._lock:
            self._data[token] = mapping
            self.version += 1

    def __delitem__(self, token: str) -> None:
        with self._lock:
            del self._data[token]
            self.version += 1

    def __iter__(self) -> Iterator[str]:
        with self._lock:
            return iter(tuple(self._data))

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()
            self.version += 1

    def __repr__(self) -> str:
        return f"MemoryMappings(count={len(self)})"

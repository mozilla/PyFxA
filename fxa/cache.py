import time
import threading
import collections

DEFAULT_CACHE_EXPIRY = 300


class MemoryCache(object):
    """Simple Memory cache."""

    def __init__(self, ttl=DEFAULT_CACHE_EXPIRY):
        self.ttl = ttl
        self.cache = {}
        self.expiry_queue = collections.deque()
        self.lock = threading.Lock()

    def get(self, key, now=None):
        with self.lock:
            if now is None:
                now = time.time()
            self._purge_expired_items(now)
            value, expires_at = self.cache.get(key, (None, 0))
            # There's a small chance that an expired item has
            # not been removed yet, due to queue ordering weirdness.
            if expires_at < now:
                return None
        return value

    def set(self, key, value, now=None):
        with self.lock:
            if now is None:
                now = time.time()
            expires_at = now + self.ttl
            self.cache[key] = (value, expires_at)
            self.expiry_queue.append((expires_at, key))

    def delete(self, key):
        if key in self.cache:
            del self.cache[key]

    def _purge_expired_items(self, now):
        while self.expiry_queue:
            (expires_at, key) = self.expiry_queue[0]
            if expires_at >= now:
                break
            # The item is expired, remove it.
            # Careful though, it may have been replaced
            # with a newer value after its expiry was enqueued.
            self.expiry_queue.popleft()
            try:
                item = self.cache.pop(key)
            except KeyError:
                pass
            else:
                if item[1] > now:
                    # It's been replaced, put it back.
                    self.cache[key] = item

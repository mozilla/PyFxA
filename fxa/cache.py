import time
DEFAULT_CACHE_EXPIRY = 300


class MemoryCache(object):
    """Simple Memory cache."""

    def __init__(self, ttl=DEFAULT_CACHE_EXPIRY):
        self.ttl = ttl
        self.cache = {}
        self.expires_at = {}

    def get(self, key):
        self._cleanup()
        value = self.cache.get(key)
        return value

    def set(self, key, value):
        self.cache[key] = value
        self.expires_at[key] = time.time() + self.ttl

    def delete(self, key):
        if key in self.cache:
            del self.cache[key]

        if key in self.expires_at:
            del self.expires_at[key]

    def _cleanup(self):
        for key, expires_at in list(self.expires_at.items()):
            if expires_at < time.time():
                self.delete(key)

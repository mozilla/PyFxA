import time

from fxa.cache import MemoryCache
from fxa.tests.utils import unittest


class TestMemoryCache(unittest.TestCase):
    def setUp(self):
        self.cache = MemoryCache()

    def test_can_get_what_has_been_set(self):
        self.cache.set('Foo', 'Bar')
        self.assertEqual(self.cache.get('Foo'), 'Bar')

    def test_expires(self):
        self.cache = MemoryCache(0.01)
        self.cache.set('Foo', 'Bar')
        time.sleep(0.01)
        self.assertIsNone(self.cache.get('Foo'))

    def test_delete(self):
        self.cache.set('Foo', 'Bar')
        self.cache.delete('Foo')
        self.assertIsNone(self.cache.get('Foo'))

    def test_delete_expires(self):
        self.cache = MemoryCache(0.01)
        self.cache.set('Foo', 'Bar')
        self.cache.delete('Foo')
        self.assertIsNone(self.cache.get('Foo'))

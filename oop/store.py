# -*- coding: utf-8 -*-

import memcache

class MyStore(object):

    def __init__(self):
        self.__store = memcache.Client('127.0.0.1')

    def get(self, key):
        return self.__store.get(key)

    def cache_get(self, key):
        return self.__store.get(key)

    def set(self, key, value):
        self.__store.set(key, value)

    def cache_set(self, key, value, alive_time=0):
        self.__store.set(key, value, alive_time)

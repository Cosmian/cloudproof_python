# -*- coding: utf-8 -*-
import redis
from cloudproof_py.findex import Findex
from cloudproof_py.findex import Key
from cloudproof_py.findex import Label
from findex_base import FindexBase


class FindexManagedRedis(FindexBase):
    """No need to implement Findex callbacks using managed backend Redis."""

    def __init__(self, key: Key, label: Label) -> None:
        super().__init__()
        self.redis = redis.Redis()

        redis_host = "localhost"
        redis_port = 6379
        redis_url = f"redis://{redis_host}:{redis_port}"

        r = redis.Redis(host=redis_host, port=redis_port, db=0)
        print(redis_url)
        r.flushdb()

        self.findex = Findex.new_with_redis_backend(key, label, redis_url, redis_url)

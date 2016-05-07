import asyncio
import ipaddress
import socket

from ._engine import PingEngine, PingError

@asyncio.coroutine
def ping(target, **kwargs):
    engine = PingEngine()
    try:
        result = yield from engine.ping(target, **kwargs)
    finally:
        engine.close()
    return result

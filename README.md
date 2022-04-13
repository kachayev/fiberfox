# FiberFox 🦊  

High-performance (D)DoS vulnerability testing toolkit. Implements various L4/7 attack vectors. The async approach to networking helps to lower CPU/RAM requirements while performing even complex network interactions.

**NOTE** 👻 The toolkit doesn't have the capabilities needed for proper performance testing of the target servers or networks. The goal is to understand the level of protection, by performing attacks specially designed to abuse common pitfalls and bypass common protection measures.

**WARNING**❗ Do not test infrastructure (servers, websites, network devices, etc) without the owner's consent. Package default settings are tuned to avoid a large unintended impact when running tests.

Inspired by [MHDDoS](https://github.com/MHProDev/MHDDoS) project.

![analysis](docs/fiberfox_analysis.png)

## Install

From PyPI:

```shell
$ pip install fiberfox
```

From sources:

```shell
$ git clone https://github.com/kachayev/fiberfox.git
$ cd fiberfox
$ python setup.py install
```

Build Docker image:

```shell
$ git clone https://github.com/kachayev/fiberfox.git
$ cd fiberfox
$ docker build -t fiberfox .
```

## Usage

Example:

```shell
$ fiberfox \
    --targets tcp://127.0.0.1:8080 http://127.0.0.1:8081 \
    --concurrency 512 \
    --rpc 1024 \
    --strategy STRESS \
    --duration-seconds 3600 \
    --proxies-config ./proxies.txt
```

Features:
* `--concurrency` (or `-c`) defines the number of async coroutines to run. Fiber doesn't create a new OS thread so you can run a lot of them with insignificant overhead. For TCP attack vectors, number of fibers roughly corresponds to the max number of open TCP connections. For UDP attacks, running too many fibers typically makes performance worse.
* Multiple targets are supported. Each fiber picks up a target by cycling over the list of them. If the fiber session is too long (e.g. when using attack vectors like `SLOW` or `CONNECTIONS`), make sure to set up more fibers than you have targets.
* Connections could be established using HTTP/SOCK4/SOCK5 proxies. Available proxies could be setup from the static configuration file or dynamically resolved from proxy providers. The tool automatically detects "dead" proxies and removes them from the pool.

More documentation about flags:

```
$ python fiberfox --help
usage: fiberfox [-h] [--targets [TARGETS ...]] [--targets-config TARGETS_CONFIG] [-c CONCURRENCY] [-s {UDP,TCP,STRESS,BYPASS,CONNECTION,SLOW,CFBUAM,AVB,GET}] [--rpc RPC] [--packet-size PACKET_SIZE]
               [-d DURATION_SECONDS] [--proxies [PROXIES ...]] [--proxies-config PROXIES_CONFIG] [--proxy-providers-config PROXY_PROVIDERS_CONFIG] [--log-level {DEBUG,INFO,ERROR,WARN}]
               [--connection-timeout-seconds CONNECTION_TIMEOUT_SECONDS]

options:
  -h, --help            show this help message and exit
  --targets [TARGETS ...]
                        List of targets, separated by spaces (if many)
  --targets-config TARGETS_CONFIG
                        File with the list of targets (target per line). Both local and remote files are supported.
  -c CONCURRENCY, --concurrency CONCURRENCY
                        Total number of fibers (for TCP attacks means max number of open connections)
  -s {UDP,TCP,STRESS,BYPASS,CONNECTION,SLOW,CFBUAM,AVB,GET}, --strategy {UDP,TCP,STRESS,BYPASS,CONNECTION,SLOW,CFBUAM,AVB,GET}
                        Flood strategy to utilize
  --rpc RPC             Number of requests to be sent to each connection
  --packet-size PACKET_SIZE
                        Packet size (in bytes)
  -d DURATION_SECONDS, --duration-seconds DURATION_SECONDS
                        How long to keep sending packets, in seconds
  --proxies [PROXIES ...]
                        List of proxy servers, separated by spaces (if many)
  --proxies-config PROXIES_CONFIG
                        File with a list of proxy servers (newline-delimited). Both local and remote files are supported.
  --proxy-providers-config PROXY_PROVIDERS_CONFIG
                        Configuration file with proxy providers (following MHDDoS configuration file format). Both local and remote files are supported.
  --reflectors-config REFLECTORS_CONFIG
                        File with the list of reflector servers (IP per line). Only required for amplification attacks. Both local and remote files are supported.
  --log-level {DEBUG,INFO,ERROR,WARN}
                        Log level (defaults to INFO)
  --connection-timeout-seconds CONNECTION_TIMEOUT_SECONDS
                        Proxy connection timeout in seconds (default: 10s)
```

## Attack Vectors

An attack vector is defined by `--strategy` option when executing the script.

Note: the package is under active development, more methods will be added soon.

### L4

L4 attacks are designed to target transport layers and thus are mainly used to overload network capacities. Requires minimum knowledge of the target.


| Strategy   | Layer | Transport | Design | Notes |
|----------- |-------|-----------|--------|-------|
| `UDP` | L4 | UDP | Simple flood: sends randomly generated UDP packets to the target | Automatically throttles fiber on receiving `NO_BUFFER_AVAILABLE` from the network device. To prevent this from happening do not configure more than 2 fibers per target when testing UDP flood attack. |
| `TCP` | L4 | TCP | Simple flood: sends RPC randomly generated TCP packets into an open TCP connection. | Supports configuration for the size of a single packet and the number of packets to be sent into each open connection. |
| `CONNECTION` | L4 | TCP | Opens TCP connections and keeps them alive as long as possible. | To be effective, this type of attack requires a higher number of fibers than usual. Note that modern servers are pretty good at handling open inactive connections. |

### UDP-based Amplification Attacks

A special class of L4 attacks.

UDP is a connectionless protocol. It does not validate the source IP address unless explicit processing is done by the application layer. It means that an attacker can easily forge the datagram to include an arbitrary source IP address. Oftentimes the application protocol is designed in a way that the packet generated in response is much larger which creates an amplification effect (hence the name). By sending such datagram to many different servers (reflectors), the attacker can generate significant traffic to the target (victim) device.

Amplification attacks implemented:

| Strategy | Protocol | Amplification Factor | Vulnerability |
|---|---|---|---|
| `RDP` | Remote Desktop Protocol (RDP) | | | 
| `CLDAP` | Connection-less Lightweight Directory Access Protocol (CLDAP) | 56 yo 70 | |
| `MEM` | Memcached | 10,000 to 50,000 | |
| `CHAR` | Character Generator Protocol (CHARGEN) | 358.8 | Char generation request |
| `ARD` | Apple Remote Desktop (ARD) | | | 
| `NTP` | Network Time Protocol (NTP) | 556.9 | [TA14-013A](https://www.cisa.gov/uscert/ncas/alerts/TA14-013A) |
| `DNS` | Domain Name System (DNS) | 28 to 54 | [TA13-088A](https://www.cisa.gov/uscert/ncas/alerts/TA13-088A) |

All amplification attacks require a list of reflection servers to be provided.

### L7

L7 attacks are designed to abuse weaknesses in application layer protocols or specific implementation details of applications (or OS kernels). Generally more powerful but might require knowledge of how the targeted system works.

| Strategy   | Layer | Transport | Design | Notes |
|----------- |-------|-----------|--------|-------|
| `GET` | L7 | TCP | Sends randomly generated HTTP GET requests over an open TCP connection | Does not require 200 OK HTTP response code (as it doesn't consume response at all). Though attack performed against load balancer or WAF might not be effective (compared to L4 TCP flood). |
| `STRESS` | L7 | TCP | Sends a sequence of HTTP requests with a large body over a single open TCP connection. | To maximize performance, make sure that the target host allows pipelining (sending a new request within a persistent connection without reading the response first). Does not require 200 OK HTTP response code (as it doesn't consume the response at all). Though attack performed against load balancer or WAF might not be effective (compared to L4 TCP flood). |
| `BYPASS` | L7 | TCP | Sends HTTP get requests over an open TCP connection, reads response back. | Chunked reading is performed by `recv` bytes from the connection, without parsing into HTTP response. |
| `SLOW` | L7 | TCP | Similarly to STRESS, issues HTTP requests and attempts to keep connection utilized by reading back a single byte and sending additional payload with time delays between send operations. |  Ideally, time delay should be set up properly to avoid connection being reset by the peer because of read timeout (depends on peer setup). |
| `CFBUAM` | L7 | TCP | Sends a single HTTP GET, after a long delay issues more requests over the same TCP connection. | |
| `AVB` | L7 | TCP | Issues HTTP GET packets into an open connection with long delays between send operations. To avoid the connection being reset by the peer because of read timeout, the maximum delay is set to 1 second. | |


## Proxies

By configuring a set of proxy servers, one can simulate distributed attack even when running the toolkit from a single machine. When proxies are available, `fiberfox` connects to them first, and establishes connections to the target from those machines. By doing so, the system can bypass the simplest IP-blocking protection measures. The toolkit supports HTTP/SOCKS4/SOCS5 protocols, and user/password authentication. It also dynamically manages a set of proxies provided to avoid using those that are not responsive or do not meet attack requirements.

There are a few considerations when using proxies that you have to keep in mind:

* The success of the attack performed now partially depends on the capacity of proxy servers. For example, when using public proxies network rate might be low because the proxy is overcrowded. In this case, consider using private infrastructure or paid clusters of dedicated proxy servers.

* Proxy servers themselves might mitigate a few attack vectors. For example, when using the "slow connection" approach, the proxy server could be configurated to throttle or close the connection. In a way "protecting" the target by doing so. Be mindful of how proxy setup intervenes with the attack mechanics (networking, protocols, etc).


## Analysis

One of the goals of the toolkit is to provide comprehensive monitoring information to guide vulnerabilities lookup.

The tool reports number of statistics per each target: number of packets, traffic, and rate. For TCP-based attacks (both L4 and L7), it also reports a histogram of packets sent within a single session (session here means traffic sent within a single open connection). Ideally, the histogram should be skewed towards the left side. It means the peer closes the connection earlier than "requests per connection" packets were sent. If it's mainly on the right, the target accepts what should be considered "garbage traffic".

Be careful with analysis. Low network rate, high frequency of connection attempts, high error rate, and more. All of those signals might indicate both the fact that the target stays strong facing the attack and that it's already dead. To get a full understanding of the level of protection, you should use monitoring information on the target side (e.g. capability to work correctly when being challenged).

Note that outbound rate is show approximately. The time measurement for sending every packet includes scheduling delays (for fibers) and select/pooling. In most cases those are negligable. Though be careful with the analysis when running 10k+ fibers.

## Contribute

* Check for open issues or open a fresh issue to start a discussion around a feature idea or a bug.
* Fork the repository on Github & fork master to `feature-*` branch to start making your changes.

## License

Release under the MIT license. See LICENSE for the full license.

```

                                        ████                                
                                    ████▒▒██                                
                                  ████  ▒▒██                                
                                ██▒▒  ▒▒▒▒▒▒██                              
                              ██▒▒██        ██                              
  ████                      ██▒▒██          ██                              
██▒▒▒▒██████                ██▒▒██      ▒▒  ████                            
██▒▒▒▒██    ████      ██████▒▒▒▒▒▒██    ▒▒▒▒██████████████                  
██▒▒    ████▒▒▒▒██████▒▒▒▒▒▒▒▒▒▒▒▒▒▒██▒▒▒▒▒▒██▒▒▒▒▒▒▒▒▒▒▒▒████              
██▒▒▒▒      ██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒██▒▒██▒▒▒▒▒▒▒▒▒▒▒▒▒▒██            
  ██▒▒      ██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒██▒▒██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒████        
  ██        ██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒██      
  ██▒▒    ██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒████▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒██    
  ██▒▒▒▒  ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒  ██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒██    
    ██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒    ██▒▒▒▒▒▒▒▒▒▒████▒▒▒▒▒▒▒▒██  
    ████▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒██      ██▒▒▒▒▒▒████▒▒▒▒▒▒▒▒▒▒▒▒██  
    ██▒▒██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒██        ██▒▒▒▒██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒██  
      ██▒▒██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒██        ██████▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒██  
      ██▒▒██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒██      ██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒██
        ████  ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒    ██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒██
          ██    ▒▒██████▒▒▒▒▒▒▒▒▒▒▒▒▒▒    ██▒▒  ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒██
          ██            ████▒▒▒▒▒▒▒▒▒▒    ██  ▒▒  ▒▒        ▒▒▒▒▒▒▒▒▒▒▒▒██  
            ██                      ██  ████  ▒▒          ▒▒▒▒▒▒▒▒▒▒▒▒▒▒██  
              ██                      ██▒▒██              ▒▒  ▒▒▒▒▒▒▒▒▒▒██  
                ██████████████████████▒▒▒▒██                    ▒▒▒▒▒▒██    
                      ██▒▒      ██▒▒▒▒▒▒▒▒██                    ▒▒▒▒██      
                      ██▒▒▒▒  ██▒▒▒▒▒▒▒▒████                  ▒▒▒▒██        
                      ██▒▒▒▒▒▒██▒▒▒▒▒▒██  ██                    ██          
                        ██████▒▒▒▒▒▒██    ██                ████            
                              ██████      ██          ██████                
                                            ██    ████                      
                                            ██████                          
```

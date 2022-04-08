# FiberFox 🦊  

High-performance (D)DoS vulnerability testing toolkit. Implements various L4/7 attack vectors. Async approach to networking helps to lower CPU/RAM requirements while performing even those attacks that are known to be problematic from implmenetation perspective.

NOTE: The toolkit doesn't have capabilities needed for proper performance testing of the target servers or networks. The goal is to understand level of protection, by performing attacks specially designed to abuse common pitfalls and to bypass common protection measures.

WARNING: Do not test infrastructure (servers, websites, network devices, etc) without owner's consent. Package default settings are tuned to avoid large impact when running tests.

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
* `--concurrency` (or `-c`) defines number of async coroutines to run. Fiber doesn't create a new OS thread so you can run a lot of them with small overhead. For TCP attack vectors, number of fibers rougly corresponds to the max number of open TCP connections. For UDP attacks, running too many fibers typically makes performance worse.
* Muliple targets are supported. Each fiber picks up target by cycling over the list of them. If fiber session is too long (e.g. when using attack vectors like `SLOW` or `CONNECTIONS`, make sure to setup more fibers than you have targets).
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
                        File with a list of proxy servers (newline-delimted). Both local and remote files are supported.
  --proxy-providers-config PROXY_PROVIDERS_CONFIG
                        Configuration file with proxy providers (following MHDDoS configuration file format). Both local and remote files are supported.
  --log-level {DEBUG,INFO,ERROR,WARN}
                        Log level (defaults to INFO)
  --connection-timeout-seconds CONNECTION_TIMEOUT_SECONDS
                        Proxy connection timeout in seconds (default: 10s)
```

## Attack Vectors

Attack vector is defined by `--strategy` option when execution the script.

Note: the package is under active development, more methods will be added soon.

### L4

* `UDP`
* `TCP`
* `CONNECTION`

### L7

* `GET`
* `STRESS`
* `BYPASS`
* `CFBUAM`
* `SLOW`
* `AVB`


## Proxies

By configuring set of proxy servers, one can simulate distributed attack even when running the toolkit from a single machine. When proxies are available, `fiberfox` connects to them first and only from those machines establishes connections to the target. By doing so, the system can bypass simplest IP-blocking protection measures. The toolkit supports HTTP/SOCKS4/SOCS5 protocols, and user/password authentication. It also dynamically manages set of proxies provided to avoid using those that are not responsive or do not meet attack requirements.

The are a few considerations when using proxies that you have to keep in mind:

* The success of the attack performed now partially depends on the capacity of proxy servers. For example, when using public proxies network rate might be low because proxy is overcrowded. In this case, consider using private infrasturucture or paid clusters of dedicated proxy servers.

* Proxy servers themselves might mitigate a few attack vectors. For example, when using "slow connection" approach, the proxy server could be configurated to throttle or close the connection. In a way "protecting" the target by doing so. Be mindful how proxy setup intervenes with the attack networking mechanics.


## Analysis

One of the goal of the toolkit is to provide comprehensive monitoring information to guide vulnerabilities lookup.

The tool reports number of statistics per each target: number of packets, traffic, rate. For TCP-based attacks (both L4 and L7), it also reports histogram of packets sent within a single session (session here means traffic sent within a single open connection). Ideally, the histogram should be skewed towards left side. It means the peer closes connection earlier than "requests per connection" packets were sent. If it's mainly on the right, the target accepts what should be considered "garbage traffic".

Be careful with analysis. Low network rate, high frequency of connection attempts, high error rate, and more. All of those signals might indicate both the fact that the target stays storng facing the attack and that it's already dead. To get full understanding of the level of protection, you should use monitoring information on the target side (e.g. capability to work correctly when being challenged).

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

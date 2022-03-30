# FiberFox 🦊  

High-performance DDoS vulnerability testing toolkit. Implements various L4/7 attack vectors. Low CPU/RAM requirements with async networking (thousands of active connections with <100Mb of memory).

Heavily inspired by [MHDDoS](https://github.com/MHProDev/MHDDoS) project.

WARNING: Do not test websites without their owners consent. Package default settings are tuned to avoid large impact when running tests.

![analysis](docs/fiberfox_analysis.png)

## Install

From sources:

```shell
$ git clone https://github.com/kachayev/fiberfox.git
$ cd fiberfox
$ python setup.py install
```

From PyPI:

```shell
$ pip install fiberfox
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
    --num-fibers 512 \
    --rpc 1024 \
    --strategy STRESS \
    -exec-time-seconds 3600 \
    --proxies ./proxies.txt
```

Features:
* `--num-fibers` defines number of async coroutines to run. Fiber doesn't create a new OS thread so you can run a lot of them with small overhead. For TCP attack vectors, number of fibers rougly corresponds to the max number of open TCP connections. For UDP attacks, running too many fibers typically makes performance worse.
* Muliple targets are supported. `--num-fibers` options defines number of fibers per target.
* Connections could be established using HTTP/SOCK4/SOCK5 proxies. Available proxies could be setup from the static configuration file or dynamically resolved from proxy providers. The tool automatically detects "dead" proxies and removes them from the pool.

More documentation about flags:

```
% fiberfox --help
usage: fiberfox [-h] [--targets [TARGETS ...]] [-n NUM_FIBERS] [-s STRATEGY] [--rpc RPC] [--packet-size PACKET_SIZE] [-t EXEC_TIME_SECONDS] [-p PROVIDERS_CONFIG] [--proxies PROXIES]

options:
  -h, --help            show this help message and exit
  --targets [TARGETS ...]
                        List of targets, separated by spaces (if many)
  -n NUM_FIBERS, --num-fibers NUM_FIBERS
                        Number of fibers per target (for TCP means max number of open connections)
  -s STRATEGY, --strategy STRATEGY
                        Flood strategy to utilize: UDP, TCP, STRESS, BYPASS
  --rpc RPC             Number of requests to be sent to each connection
  --packet-size PACKET_SIZE
                        Packet size (in bytes)
  -t EXEC_TIME_SECONDS, --exec-time-seconds EXEC_TIME_SECONDS
                        How long to keep sending packets, in seconds
  -p PROVIDERS_CONFIG, --providers-config PROVIDERS_CONFIG
                        Configuration file with proxy providers
  --proxies PROXIES     List proxies (ip:port, line-separated)
```

## Attack Vectors

Attack vector is defined by `--strategy` option when execution the script.

Note: the package is under active development, more methods will be added soon.

### L4

* `UDP`
* `TCP`
* `CONNECTION`

### L7

* `BYPASS`
* `STRESS`
* `CFBUAM`
* `SLOW`
* `AVB`

## Analysis

The tool reports number of statistics per each target: number of packets, traffic, rate. For TCP-based attacks (both L4 and L7), it also reports histogram of packets sent within a single session (session here means traffic sent within a single open connection). Ideally, the histogram should be skewed towards right side. If otherwise is true, it means the peer closes connection earlier than "requests per connection" packets were sent. This might indicate that the attack strategy choosen is not effective. 

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

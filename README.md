# capirca

[![BuildStatus](https://travis-ci.org/google/capirca.svg?branch=master)](https://travis-ci.org/google/capirca)
<!-- <a href="https://github.com/google/capirca/actions/" target="_blank"><img src="https://github.com/google/capirca/workflows/build/badge.svg?branch=master"></a> -->

- [About](#about)
- [The basics](#the-basics)
  - [Anatomy of a policy file](#anatomy-of-a-policy-file)
      - [Headers](#headers)
      - [Terms](#terms)
      - [Tokens](#tokens)
  - [Keywords](#keywords)
      - [Required](#required)
      - [Optional](#optional)
  - [Includes](#includes)
  - [Example](#example)
      - [Term Keywords By Generator](#term-keywords-by-generator)
      - [Term Examples](#term-examples)
      - [Example Policy File](#example-policy-file)
- [Getting Started](#getting-started)
  - [Installation](#installation)
      - [From Source](#from-source)
      - [Package Manager](#package-manager)
  - [Basic Usage](#basic-usage)
  - [Python Package](#python-package)
  - [Running with Docker](#running-with-docker)
- [Miscellaneous](#miscellaneous)

## About

Capirca is designed to utilize common definitions of networks, services and
high-level policy files to facilitate the development and manipulation of
network access control lists (ACLs) for various platforms. It was developed by
Google for internal use, and is now open source.

Capirca consist of `capirca` Python package and the `capirca` tool.

The typical usage workflow consists of the following steps:

1.  Create **object definitions** containing "network" and "service" definitions
1.  Create a **access control policy** defining the desired state of access
    control and referencing the **object definitions** together with desired
    firewall platforms
1.  Generate ACL configurations by running `capirca` command referencing the
    access control policy and the object definitions. The command triggers a
    **generator** for each of the firewall platforms.

## The basics

At a high-level capirca rationalizes objects (networks, services) against a
security definition (.pol file) to generate a specific device configuration file
via a platform specific **ACL generator**. Before getting started some objects
must exist, the below table summarizes where objects are stored:

path              | description
----------------- | -----------------------------------------
/def/NETWORK.net  | a list of **network objects** definitions
/def/SERVICES.svc | a list of **service objects** definitions

Each network or service definition file has a very simple structure. A token is
defined, e.g. `GUEST_NET`, followed by an equal sign, then followed by a
definition, e.g. `10.10.10.0/24`, and optional description field, e.g. `# guest
network range`.

```
GUEST_NET = 10.10.10.0/24      # guest network range
```

The tool populates the **access control policy** from `.pol` files in a
particular directory, e.g. [`policies/`](./policies/). The tool searches
recursively for `.pol` files and add them to the policy, .e.g `.pol` files are
located in [`policies/pol`](./policies/pol).

Additionally, the `.pol` files MAY reference other policy definition files
located outside of the directory by using `include` directive. Please see
[Includes](#includes) section for documentation.

### Network Objects

The files with `.net` extension contain the definitions of network objects, e.g.
IP networks and hosts. The following definition creates `INTERNAL` and `RFC1918`
network objects in the object definitions, whether `INTERNAL` references the IP
ranges of RFC 1918 defined in the `RFC1918`.

```
RFC1918 = 10.0.0.0/8      # non-public
          172.16.0.0/12   # non-public
          192.168.0.0/16  # non-public

INTERNAL = RFC1918
```

[Back to Top](#table-of-contents)

### Service Objects

The files with `.svc` extension contain the definitions of service objects, e.g.
ports and protocols.

```
DNS = 53/tcp  # transfers
      53/udp  # queries
```

[Back to Top](#table-of-contents)

### Object Nesting

The nesting of tokens is permitted only when both tokens are of the same type.
The referencing of a "network" object by "service" object is not allowed, and
vice versa.

The examples of nesting of the network and service object follow.

```
HTTP = 80/tcp               # common web
HTTPS = 443/tcp             # SSL web
HTTP_8080 = 8080/tcp        #  web on non-standard port
WEB_SERVICES = HTTP HTTP_8080 HTTPS  # all our web services
DB_SERVICES = 3306/tcp      # allow db access
              HTTPS         # and SSL access
NYC_NETWORK = 200.1.1.0/24  # New York office
ATL_NETWORK = 200.2.1.0/24  # Atlanta office
DEN_NETWORK = 200.5.1.0/24  # Denver office
REMOTE_OFFICES = NYC_NETWORK
                 ATL_NETWORK
                 DEN_NETWORK
```

The network objects may reference both IPv4 and IPv6 addresses at the same time.

```
LOOPBACK = 127.0.0.1/32          # loopback in IPv4
           ::1/128               # loopback in IPv6
LINKLOCAL = FE80::/10            # IPv6 link local address
NYC_NETWORK = 172.16.1.0/24      # NYC IPv4
              2620:0:10A1::/48   # NYC IPv6
```

[Back to Top](#table-of-contents)

### Anatomy of a policy file

A policy file (/policies/pol/something.pol) has the security policy written
using capirca specific meta-language and format. There are specific sections
(e.g: header) that tell capirca how to generate the output configuration of the
security policy.

#### Headers

The header section defines:

*   **target** firewall platforms (which ACL generator to use)
*   passes **additional arguments** to the generator responsible for that
    platform.

A single header may have many targets within a section. It will result in
multiple outputs being generated for that policy.

#### Terms

The **term** sections defines the access control rules within an ACL, it contains
keywords followed by an object (service or network) and policy decision ("action" keyword).

The term section specifies the network flow metadata for ACL matching.

*   Addresses
*   Ports
*   Protocols
*   Action (allow/deny)

Inside a `term` a mandatory keyword will be found followed by an object token
for rule evaluation.

#### Tokens

Tokens are the names of services and networks loaded from the object
definitions. Example:

token_name    | definition
------------- | --------------
"HTTPS"       | 443
"NYC_NETWORK" | 192.168.0.0/24

### Keywords

| keyword  | description                                                      |
| -------- | ---------------------------------------------------------------- |
| required | **must be supported by all output policy generators**            |
| optional | available in a subset of the generators and are intended to      |
:          : provide additional flexibility when developing policies for that :
:          : specific target platform                                         :

#### Required

*   **action**
    *   accept
    *   deny
    *   reject
    *   next
    *   reject-with-tcp-rst
*   **comment**
    *   a text comment enclosed in double-quotes. Comments may span multiple
        lines if desired.
*   **destination-address**
    *   one or more destination address tokens.
*   **destination-exclude**
    *   exclude one or more address tokens from the specified
        destination-address.
*   **destination-port**
    *   one or more service definition tokens.
*   **icmp-type**
    *   specific icmp-type code to match (IPv4/IPv6 types vary).
        *   IPv4:
        *   echo-reply
        *   unreachable
        *   source-quench
        *   redirect
        *   alternate-address
        *   echo-request
        *   router-advertisement
        *   router-solicitation
        *   time-exceeded
        *   parameter-problem
        *   timestamp-request
        *   timestamp-reply
        *   information-request
        *   information-reply
        *   mask-request
        *   mask-reply
        *   conversion-error
        *   mobile-redirect
        *   IPv6:
        *   destination-unreachable
        *   packet-too-big
        *   time-exceeded
        *   parameter-problem
        *   echo-request
        *   echo-reply
        *   multicast-listener-query
        *   multicast-listener-report
        *   multicast-listener-done
        *   router-solicit
        *   router-advertisement
        *   neighbor-solicit
        *   neighbor-advertisement
        *   redirect-message
        *   router-renumbering
        *   icmp-node-information-query
        *   icmp-node-information-response
        *   inverse-neighbor-discovery-solicitation
        *   inverse-neighbor-discovery-advertisement
        *   version-2-multicast-listener-report
        *   home-agent-address-discovery-request
        *   home-agent-address-discovery-reply
        *   mobile-prefix-solicitation
        *   mobile-prefix-advertisement
        *   certification-path-solicitation
        *   certification-path-advertisement
        *   multicast-router-advertisement
        *   multicast-router-solicitation
        *   multicast-router-termination
*   **option**
    *   connection options.
        *   **established**
            *   only permit established connections; implements tcp-established
                flag if protocol is tcp only, otherwise adds 1024-65535 to
                required destination-ports.
        *   **tcp-established**
            *   only permit established tcp connections, usually checked based
                on TCP flag settings. If protocol UDP is included in term, only
                adds 1024-65535 to required destination-ports.
        *   **sample**
            *   not supported by all generators. Samples traffic for netflow.
        *   **intial**
            *   currently only supported by juniper generator. Appends
                tcp-initial to the term.
        *   **rst**
            *   currently only supported by juniper generator. Appends
                "tcp-flags rst" to the term.
        *   **first-fragment**
            *   currently only supported by juniper generator. Appends
                'first-fragment' to the term.
*   **protocol**
    *   network protocols this term will match, such as tcp, udp, icmp, or a
        numeric value.
*   **protocol-except**
    *   network protocols that should be excluded from the protocol
        specification. This is rarely used.
*   **source-address**
    *   one or more source address tokens.
*   **source-exclude**
    *   exclude one or more address tokens from the specified source-address.
*   **source-port**
    *   one or more service definition tokens.
*   **verbatim**
    *   this specifies that the text enclosed within quotes should be rendered
        into the output without interpretation or modification. This is
        sometimes used as a temporary workaround while new required features are
        being added.

#### Optional

WARNING: These terms may or may not function properly on all generators. Always
refer to the generator specific documentation and code base.

*   **address**
    *   one or more network address tokens matches either source or destination.
*   **counter**
    *   (Juniper only) enable filter-based generic routing encapsulation (GRE)
        tunneling using the specified tunnel template.
*   **destination-prefix**
    *   (Juniper only) specify destination-prefix matching (e.g. source-prefix`
        configured-neighbors-only).
*   **ether-type**
    *   (Juniper only) specify matching ether-type(e.g. ether-type` arp).
*   **fragement-offset**
    *   (Juniper only) specify a fragment offset of a fragmented packet.
*   **logging**
    *   (Juniper, speedway/iptables) specify that this packet should be logged
        via syslog.
*   **loss-priority**
    *   (Juniper only) specify loss priority.
*   **packet-length**
    *   (Juniper only) specify packet length.
*   **policer**
    *   (Juniper only) specify which policer to apply to matching packets.
*   **precedence**
    *   (Juniper only) specify precendence.
*   **qos**
    *   (Juniper only) apply quality of service classification to matching
        packets (e.g. qos` af4).
*   **routing-instance**
    *   (iptables, speedway only) specify specific interface a term should apply
        to (e.g. source-interface` eth3).
*   **source-prefix**
    *   (Juniper only) specify source-prefix matching (e.g. source-prefix,
        configured-neighbors-only).
*   **traffic-type**
    *   (Juniper only) specify traffic-type.

### Includes

Policy files support the use of `#include` statements. An include may be used to
avoid duplication of commonly used text, such as a group of terms that permit or
block specific types of traffic.

An include directive will result in the contents of the included file being
injected into the current policy file in the exact location of the `#include`
directive. An example include:

```
#include 'includes/untrusted-networks-blocking.inc'
```
NOTE: Includes are only read from the subdirectories of your base_directory,
all other directories will error out.

The `.inc` file extension and the `includes/` folder is not required but it is
recommended to be used as a best practice and for easier readability.

### Example

WARNING: Not all generators have the same configuration options or feature set.

```
header {
  target:: paloalto from-zone internal to-zone external
}

term ping-gdns{
  source-address:: INTERNAL
  destination-address:: GOOGLE_DNS
  protocol:: icmp
  action:: accept
}
```

The above example tells capirca to use paloalto.py to generate a platform
specific configuration for Palo Alto.

The security policy is written within the term section using the meta-language:

*   name/description: ping-gdns
*   source: any INTERNAL network (check /def/NETWORK.net definition of
    'INTERNAL')
*   destination: service object named GOOGLE_DNS
*   protocol: icmp
*   action: accept

The above ACL controls traffic in one direction only (outbound towards the
service) and there should be another header and term to control the traffic in
the opposite direction. Unless the target generator features the ability to
automatically create bi-directional configuration from a single ACL term. Always
check the documentation of the generator or validate the output generated to
validate final configuration and policy interpretation.

#### Term Keywords By Generator

The following list contains links to the documentation of the individual policy
generators:

<!-- begin-generator-term-links -->

*   [`arista`](./doc/generators/arista.md): Arista
*   [`aruba`](./doc/generators/aruba.md): Aruba
*   [`brocade`](./doc/generators/brocade.md): Brocade
*   [`cisco`](./doc/generators/cisco.md): Cisco
*   [`ciscoasa`](./doc/generators/ciscoasa.md): Cisco ASA
*   [`cisconx`](./doc/generators/cisconx.md): Cisco NX
*   [`ciscoxr`](./doc/generators/ciscoxr.md): Cisco XR
*   [`cloudarmor`](./doc/generators/cloudarmor.md): cloudarmor
*   [`gce`](./doc/generators/gce.md): GCE
*   `gcp_hf`
*   [`ipset`](./doc/generators/ipset.md): ipset
*   [`iptables`](./doc/generators/iptables.md): iptables
*   [`juniper`](./doc/generators/juniper.md): Juniper
*   [`juniperevo`](./doc/generators/juniperevo.md): Juniper EVO
*   [`junipermsmpc`](./doc/generators/junipermsmpc.md): Juniper
*   [`junipersrx`](./doc/generators/junipersrx.md): Juniper SRX
*   [`k8s`](./doc/generators/k8s.md): Kubernetes NetworkPolicy
*   [`nftables`](./doc/generators/nftables.md): nftables
*   [`nsxv`](./doc/generators/nsxv.md): NSX
*   [`packetfilter`](./doc/generators/packetfilter.md): PacketFilter
*   [`paloaltofw`](./doc/generators/paloaltofw.md): Palo Alto PANOS
*   [`pcap`](./doc/generators/pcap.md): PcapFilter
*   [`sonic`](./doc/generators/sonic.md): SONiC ACLs in config_db.json format
*   [`speedway`](./doc/generators/speedway.md): Speedway
*   [`srxlo`](./doc/generators/srxlo.md): Stateless Juniper ACL
*   [`windows_advfirewall`](./doc/generators/windows_advfirewall.md): Windows
    Advanced Firewall <!-- begin-generator-term-links -->

[Back to Top](#table-of-contents)

#### Term Examples

The following are examples of how to construct a term, and assumes that naming
definition tokens used have been defined in the definitions files.

*   Block incoming bogons and spoofed traffic

```
term block-bogons {
  source-address:: BOGONS RFC1918
  source-address:: COMPANY_INTERNAL
  action:: deny
}
```

*   Permit Public to Web Servers

```
term permit-to-web-servers {
  destination-address:: WEB_SERVERS
  destination-port:: HTTP
  protocol:: tcp
  action:: accept
}
```

*   Permit Replies to DNS Servers From Primaries

```
term permit-dns-tcp-replies {
  source-address:: DNS_PRIMARIES
  destination-address:: DNS_SECONDARIES
  source-address:: DNS
  protocol:: tcp
  option:: tcp-established
  action:: accept
}
```

*   Permit All Corporate Networks, Except New York, to FTP Server

This will "subtract" the `CORP_NYC_NETBLOCK` from the `CORP_NETBLOCKS` token.
For example, assume `CORP_NETBLOCKS` includes `200.0.0.0/20`, and
`CORP_NYC_NETBLOCK` is defined as `200.2.0.0/24`. The `source-exclude` will
remove the NYC netblock from the permitted source addresses. If the excluded
address is not contained with the source address, nothing is changed.

```
term allow-inbound-ftp-from-corp {
  source-address:: CORP_NETBLOCKS
  source-exclude:: CORP_NYC_NETBLOCK
  destination-port:: FTP
  protocol:: tcp
  action:: accept
}
```

[Back to Top](#table-of-contents)

#### Example Policy File

Below is an example policy file for a Juniper target platform. It contains two
filters, each with a handful of terms. This examples assumes that the network
and service naming definition tokens have been defined.

```
header {
  comment:: "edge input filter for sample network."
  target:: juniper edge-inbound
}
term discard-spoofs {
  source-address:: RFC1918
  action:: deny
}
term permit-ipsec-access {
  source-address:: REMOTE_OFFICES
  destination-address:: VPN_HUB
  protocol:: 50
  action:: accept
}
term permit-ike-access {
  source-address:: REMOTE_OFFICES
  destination-address:: VPN_HUB
  protocol:: udp
  destination-port:: IKE
  action:: accept
}
term permit-public-web-access {
  destination-address:: WEB_SERVERS
  destination-port:: HTTP HTTPS HTTP_8080
  protocol:: tcp
  action:: accept
}
term permit-tcp-replies {
  option:: tcp-established
  action:: accept
}
term default-deny {
  action:: deny
}

header {
  comment:: "edge output filter for sample network."
  target:: juniper edge-outbound
}
term drop-internal-sourced-outbound {
  destination-address:: INTERNAL
  destination-address:: RESERVED
  action:: deny
}
term reject-internal {
  source-address:: INTERNAL
  action:: reject
}
term default-accept {
  action:: accept
}
```

[Back to Top](#table-of-contents)

## Getting Started

### Installation

#### From Source

If `setuptools` Python package is not installed on your system, install it: For
example, the following commands installs the package with `apt` package manager.

```bash
sudo apt-get install python3-pip python3-setuptools
```

Next, to install `capirca` from source, clone the `capirca` repository and run
its installer:

```bash
git clone https://github.com/google/capirca.git
cd capirca/
python3 setup.py install --user
```

Typically, when provided `--user` argument, the installer creates the following
files, where `3.8` is Python version and `2.0.0` is the version of `capirca`:

*   `~/.local/bin/capirca`
*   `~/.local/lib/python3.8/site-packages/capirca-2.0.0-py3.8.egg`

If necessary, remove build files:

```bash
rm -rf build capirca.egg-info dist
```

Next, test `capirca` by generating sample output filters for Cisco, Juniper,
iptables, and other firewall platforms.

```bash
~/.local/bin/capirca
```

The generation of sample output while in the `capirca`'s source code directory
does not require command line parameters, because `capirca` inherits default
settings from the following configuration (see `capirca/utils/config.py`).

```json
{
    'base_directory': './policies',
    'definitions_directory': './def',
    'policy_file': None,
    'output_directory': './filters',
    'optimize': False,
    'recursive': True,
    'debug': False,
    'verbose': False,
    'ignore_directories': ['DEPRECATED', 'def'],
    'max_renderers': 10,
    'shade_check': False,
    'exp_info': 2
}
```

Although the `policy_file` is `None`, the tool processes all policies located in
`base_directory`, i.e. `./policies`. The tool loads network and service
definitions from `definitions_directory`. The tool output generated ACLs to the
root of the source directory because `output_directory` is `./filters`.

[Back to Top](#table-of-contents)

#### Package Manager

Currently, the PyPI is out of date. Nevertheless, a user can install an older
version of `capirca` with `pip`:

```py
pip install capirca --user
```

[Back to Top](#table-of-contents)

### Basic Usage

There are a number of command-line arguments that can be used with `capirca`.

```
$ ~/.local/bin/capirca --helpfull

       USAGE: capirca [flags]
flags:

absl.app:
  -?,--[no]help: show this help
    (default: 'false')
  --[no]helpfull: show full help
    (default: 'false')
  --[no]helpshort: show this help
    (default: 'false')
  --[no]helpxml: like --helpfull, but generates XML output
    (default: 'false')
  --[no]only_check_args: Set to true to validate args and exit.
    (default: 'false')
  --[no]pdb: Alias for --pdb_post_mortem.
    (default: 'false')
  --[no]pdb_post_mortem: Set to true to handle uncaught exceptions with PDB post mortem.
    (default: 'false')
  --profile_file: Dump profile information to a file (for python -m pstats). Implies --run_with_profiling.
  --[no]run_with_pdb: Set to true for PDB debug mode
    (default: 'false')
  --[no]run_with_profiling: Set to true for profiling the script. Execution will be slower, and the output format might change over time.
    (default: 'false')
  --[no]use_cprofile_for_profiling: Use cProfile instead of the profile module for profiling. This has no effect unless --run_with_profiling
    is set.
    (default: 'true')

absl.logging:
  --[no]alsologtostderr: also log to stderr?
    (default: 'false')
  --log_dir: directory to write logfiles into
    (default: '')
  --logger_levels: Specify log level of loggers. The format is a CSV list of `name:level`. Where `name` is the logger name used with
    `logging.getLogger()`, and `level` is a level name  (INFO, DEBUG, etc). e.g. `myapp.foo:INFO,other.logger:DEBUG`
    (default: '')
  --[no]logtostderr: Should only log to stderr?
    (default: 'false')
  --[no]showprefixforinfo: If False, do not prepend prefix to info messages when it's logged to stderr, --verbosity is set to INFO level,
    and python logging is used.
    (default: 'true')
  --stderrthreshold: log messages at this level, or more severe, to stderr in addition to the logfile.  Possible values are 'debug', 'info',
    'warning', 'error', and 'fatal'.  Obsoletes --alsologtostderr. Using --alsologtostderr cancels the effect of this flag. Please also note
    that this flag is subject to --verbosity and requires logfile not be stderr.
    (default: 'fatal')
  -v,--verbosity: Logging verbosity level. Messages logged at this level or lower will be included. Set to 1 for debug logging. If the flag
    was not set or supplied, the value will be changed from the default of -1 (warning) to 0 (info) after flags are parsed.
    (default: '-1')
    (an integer)

capirca.capirca:
  --base_directory: The base directory to look for acls; typically where you'd find ./corp and ./prod
    (default: './policies')
  --config_file: A yaml file with the configuration options for capirca;
    repeat this option to specify a list of values
  --[no]debug: Debug messages
    (default: 'false')
  --definitions_directory: Directory where the definitions can be found.
    (default: './def')
  --exp_info: Print a info message when a term is set to expire in that many weeks.
    (default: '2')
    (an integer)
  --ignore_directories: Don't descend into directories that look like this string
    (default: 'DEPRECATED,def')
    (a comma separated list)
  --max_renderers: Max number of rendering processes to use.
    (default: '10')
    (an integer)
  -o,--[no]optimize: Turn on optimization.
    (default: 'False')
  --output_directory: Directory to output the rendered acls.
    (default: './filters')
  --policy_file: Individual policy file to generate.
  --[no]recursive: Descend recursively from the base directory rendering acls
    (default: 'true')
  --[no]shade_check: Raise an error when a term is completely shaded by a prior term.
    (default: 'false')
  --[no]verbose: Verbose messages
    (default: 'false')

absl.flags:
  --flagfile: Insert flag definitions from the given file into the command line.
    (default: '')
  --undefok: comma-separated list of flag names that it is okay to specify on the command line even if the program does not define a flag
    with that name.  IMPORTANT: flags in this list that have arguments MUST use the --flag=value format.
    (default: '')
```

Notably, the `--config_file PATH` argument allows passing one or more yaml
configuration files. These files will be prioritized from left to right, i.e.
any duplicate configurations will be overriden, not merged.

The command line arguments take precendence over any settings passed via the
configuration files.

The default `capirca` configurations in a YAML format follows:

```yaml
---
base_directory: ./policies
definitions_directory: ./def
output_directory: ./
optimize: false
recursive: true
debug: false
verbose: false
ignore_directories:
  - DEPRECATED
  - def
max_renderers: 10
shade_check: true
exp_info: 2
```

[Back to Top](#table-of-contents)

### Python Package

The `capirca` tool uses `capirca` Python package.

Therefore, there is a way to access `capirca` programmatically.

*   `policies/sample_paloalto.pol`
*   `def/SERVICES.svc`
*   `def/NETWORK.net`

Provided you have the following files in your directory, the following code
snippets create a `naming` definitions object, policy object, and render
generator filter output.

**NOTE**: Paste the code snippets one line at a time.

First, start Python interpreter:

```
$ python3
Python 3.8.7 (default, Dec 22 2020, 10:37:26)
[GCC 10.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>>
```

Next, import `naming` library and create `naming` object from definitions files
in `./def` directory.

```py
from pprint import pprint
from capirca.lib import naming
defs = naming.Naming('./def')
pprint(defs)
<capirca.lib.naming.Naming object at 0x7f8421b57280>
```

The `defs` object follows:

```
<capirca.lib.naming.Naming object at 0x7f8421b57280>
```

The `Naming` object has various methods. The `GetServiceNames` method returns
the service name tokens.

```
>>> dir(defs)
['GetIpParents', 'GetNet', 'GetNetAddr', 'GetNetChildren', 'GetServiceNames',
 <...intentionally omitted ..>
'unseen_networks', 'unseen_services']
>>>

>>> pprint(defs.GetServiceNames())
['WHOIS',
 'SSH',
 <...intentionally omitted ..>
 'TRACEROUTE']
>>>
```

Then, import `policy` library, read in the policy configuration data from
`./policies/sample_paloalto.pol`, and create a policy object.

```py
from capirca.lib import policy
conf = open('./policies/sample_paloalto.pol').read()
pol = policy.ParsePolicy(conf, defs, optimize=True)
```

The policy object follows:

```
>>> pprint(pol)
Policy: {Target[paloalto], Comments [], Apply groups: [], except: []:[ name: ping-gdns
  source_address: [IPv4('10.0.0.0/8'), IPv4('172.16.0.0/12'), IPv4('192.168.0.0/16')]
  destination_address: [IPv4('8.8.4.4/32'), IPv4('8.8.8.8/32'), IPv6('2001:4860:4860::8844/128'), IPv6('2001:4860:4860::8888/128')]
  protocol: ['icmp']
  action: ['accept'],  name: dns-gdns
  source_address: [IPv4('10.0.0.0/8'), IPv4('172.16.0.0/12'), IPv4('192.168.0.0/16')]
  destination_address: [IPv4('8.8.4.4/32'), IPv4('8.8.8.8/32'), IPv6('2001:4860:4860::8844/128'), IPv6('2001:4860:4860::8888/128')]
  protocol: ['tcp']
  destination_port: [(53, 53)]
  action: ['accept'],  name: allow-web-outbound
  source_address: [IPv4('10.0.0.0/8'), IPv4('172.16.0.0/12'), IPv4('192.168.0.0/16')]
  protocol: ['tcp']
  destination_port: [(80, 80), (443, 443)]
  action: ['accept']], Target[paloalto], Comments [], Apply groups: [], except: []:[ name: allow-icmp
  protocol: ['icmp']
  action: ['accept'],  name: allow-only-pan-app
  action: ['accept']
  pan_application: ['http'],  name: allow-web-inbound
  destination_address: [IPv4('200.1.1.1/32'), IPv4('200.1.1.2/32')]
  protocol: ['tcp']
  destination_port: [(80, 80), (443, 443)]
  action: ['accept']
  pan_application: ['ssl', 'http']]}
>>>
```

Next, import a generator library (here `paloaltofw` for Palo Alto firewalls) and
output a policy in the desired format.

```py
from capirca.lib import paloaltofw
for header in pol.headers:
  if 'paloalto' in header.platforms:
    jcl = True
  if jcl:
    output = paloaltofw.PaloAltoFW(pol, 1)
    print(output)
```

The following code initiates Palo Alto firewall ACL model with the default
expiration of 1 week.

```
paloaltofw.PaloAltoFW(pol, 1)
```

[Back to Top](#table-of-contents)

### Running with Docker

If your use case is to just use the CLI and you don't want to go through the
process of installing `capirca`, you can use the dockerized version of the tool.

When using `docker`, mount your working directory to the `/data` directory of
the container and pass command-line arguments in the following way.

```bash
docker run -v "${PWD}:/data" docker.pkg.github.com/google/capirca/capirca:latest
docker run -v "${PWD}:/data" docker.pkg.github.com/google/capirca/capirca:latest --helpfull
docker run -v "${PWD}:/data" docker.pkg.github.com/google/capirca/capirca:latest --config_file /data/path/to/config
```

[Back to Top](#table-of-contents)

## Miscellaneous

### Security considerations

The Capirca threat model assumes some control and verification of policy
definitions (in .pol files). This is either through human user verification,
or that policies are generated by upstream systems that enforce correctness.

It is recommended that the ACL generated by Capirca is always tested for
correctness before being applied to production. Not all generators support every
feature, configuration option or term keywords. When something is unsupported,
Capirca will error out. But due to the sensitive nature of network ACLs, it is
always recommended to test any new generator being used, or new policies being
generated.

### Additional documentation

*   [aclcheck library](./doc/wiki/AclCheck-library.md)
*   [policy reader library](./doc/wiki/PolicyReader-library.md)
*   [policy library](./doc/wiki/Policy-library.md)
*   [naming library](./doc/wiki/Naming-library.md)
*   [capirca design doc](./doc/wiki/Capirca-design.md)

External links, resources and references:

*   [Brief Overview (4 slides):](https://docs.google.com/present/embed?id=dhtc9k26_13cz9fphfb&autoStart=true&loop=true&size=1)
*   [Nanog49; Enterprise QoS](http://www.nanog.org/meetings/nanog49/presentations/Tuesday/Chung-EnterpriseQoS-final.pdf)
*   [Capirca Slack at NetworkToCode](https://networktocode.slack.com/)

[Back to Top](#table-of-contents)

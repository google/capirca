# Introduction
The access control policy describes the desired network security policy through the use of a high-level language that uses keywords and tokens. Tokens are derived from the naming libraries import of definition files.

# Basic Policy File Format
A policy file consists of one or more filters, with each filter containing one or more terms. Each term specifies basic network filter information, such as addresses, ports, protocols and actions.

A policy file consists of one or more header sections, with each header section being followed by one or more terms.

A header section is typically used to specify a filter for a given direction, such as an INPUT filter on Iptables. A second header section will typically be included in the policy to specify the OUTPUT filter.

In addition, the policy language support "include files" which inject the text from the included file into the policy at the specified location. For more details, see the Includes section.

# Header Section
Each filter is identified with a header section. The header section is used to define the type of filter, a descriptor or name, direction (if applicable) and format (ipv4/ipv6).

For example, the following simple header defines a filter that can generate output for 'Juniper', 'cisco' and 'iptables' formats.

```
header {
  comment:: "Example header for Juniper and iptables filter."
  target:: juniper edge-filter
  target:: speedway INPUT
  target:: iptables INPUT
  target:: cisco edge-filter
}
```

Notice that the first target has 2 arguments: `juniper` and `edge_filter`. The first argument specifies that the filter can be rendered for Juniper JCLs, and that the output filter should be called `edge_filter`.

The second target also has 2 arguments: `speedway` and `INPUT`. Since Speedway/Iptables has specific inherent filters, such as `INPUT`, `OUTPUT` and `FORWARD`, the target specification for iptables usually points to one of these filters although a custom chain can be specified (usually for combining with other filters rules through the use of a jump from one of the default filters)

Likewise, the 4th target, `cisco` simply specifies the name of the access control list to be generated.

# Target Platforms
Each target platform may have different possible arguments, which are detailed in the following subsections.

## Juniper
The `juniper` header designation has the following format:

```
target:: Juniper [filter name] {inet|inet6|bridge}
```

* `filter name`: defines the name of the Juniper filter.
* `inet`: specifies the output should be for IPv4 only filters. This is the default format.
* `inet6`: specifies the output be for IPv6 only filters.
* `bridge`: specifies the output should render a Juniper bridge filter.

When `inet4` or `inet6` is specified, naming tokens with both IPv4 and IPv6 filters will be rendered using only the specified addresses.

The default format is `inet4`, and is implied if not other argument is given.

## Cisco
The `cisco` header designation has the following format:

```
target:: cisco [filter name] {extended|standard|object-group|inet6|mixed}
```

* `filter name`: defines the name or number of the cisco filter.
* `extended`: specifies that the output should be an extended access list, and the filter name should be non-numeric. This is the default option.
* `standard`: specifies that the output should be a standard access list, and the filter name should be numeric and in the range of 1-99.
* `object-group`: specifies this is a cisco extended access list, and that object-groups should be used for ports and addresses.
* `inet6`: specifies the output be for IPv6 only filters.
* `mixed`: specifies output will include both IPv6 and IPv4 filters.

When `inet4` or `inet6` is specified, naming tokens with both IPv4 and IPv6 filters will be rendered using only the specified addresses.

The default format is `inet4`, and is implied if not other argument is given.

## Iptables
:pencil2: _NOTE: Iptables produces output that must be passed, line by line, to the 'iptables/ip6tables' command line. For 'iptables-restore' compatible output, please use the Speedway generator._

The Iptables header designation has the following format:

```
target:: iptables [INPUT|OUTPUT|FORWARD|custom] {ACCEPT|DROP} {truncatenames} {nostate} {inet|inet6}
```

* `INPUT`: apply the terms to the input filter.
* `OUTPUT`: apply the terms to the output filter.
* `FORWARD`: apply the terms to the forwarding filter.
* `custom`: create the terms under a custom filter name, which must then be linked/jumped to from one of the default filters (e.g. `iptables -A input -j custom`)
* `ACCEPT`: specifies that the default policy on the filter should be 'accept'.
* `DROP`: specifies that the default policy on the filter should be to 'drop'.
* `inet`: specifies that the resulting filter should only render IPv4 addresses.
* `inet6`: specifies that the resulting filter should only render IPv6 addresses.
* `truncatenames`: specifies to abbreviate term names if necessary (see lib/iptables.py:CheckTermLength for abbreviation table)
* `nostate`: specifies to produce 'stateless' filter output (e.g. no connection tracking)
Speedway

:pencil2: _NOTE: Speedway produces Iptables filtering output that is suitable for passing to the `iptables-restore` command._

## Speedway
The Speedway header designation has the following format:

```
target:: speedway [INPUT|OUTPUT|FORWARD|custom] {ACCEPT|DROP} {truncatenames} {nostate} {inet|inet6}
```

* `INPUT`: apply the terms to the input filter.
* `OUTPUT`: apply the terms to the output filter.
* `FORWARD`: apply the terms to the forwarding filter.
* `custom`: create the terms under a custom filter name, which must then be linked/jumped to from one of the default filters (e.g. iptables -A input -j custom)
* `ACCEPT`: specifies that the default policy on the filter should be 'accept'.
* `DROP`: specifies that the default policy on the filter should be to 'drop'.
* `inet`: specifies that the resulting filter should only render IPv4 addresses.
* `inet6`: specifies that the resulting filter should only render IPv6 addresses.
* `truncatenames`: specifies to abbreviate term names if necessary (see lib/iptables.py:CheckTermLength for abbreviation table)
* `nostate`: specifies to produce 'stateless' filter output (e.g. no connection tracking)

## NSX
The nsx header designation has the following format:
```
target:: nsxv {section_name} {inet|inet6|mixed} section-id securitygroup securitygroupId
```

* `section_name`: specifies the name of the section all terms in this header apply to.
* `inet`: specifies that the resulting filter should only render IPv4 addresses.
* `inet6`: specifies that the resulting filter should only render IPv6 addresses.
* `mixed`: specifies that the resulting filter should render both IPv4 and IPv6 addresses.
* `sectionId`: specifies the Id for the section [optional]
* `securitygroup`: specifies that the appliedTo should be security group [optional]
* `securitygroupId`: specifies the Id of the security group [mandatory if securitygroup is given]

:pencil2: _NOTE: Required keywords option and verbatim are not supported in NSX)_

# Terms Section
Terms defines access control rules within a filter. Once the filter is defined in the header sections, it is followed by one or more terms. Terms are enclosed in brackets and use keywords to specify the functionality of a specific access control.

A term section begins with the keyword term, followed by a term name. Opening and closing brackets follow, which include the keywords and tokens to define the matching and action of the access control term.

The keywords fall into two categories, those are are required to be supported by all output generators, and those that are optionally supported by each generator. Optional keywords are intended to provide additional flexibility when developing policies on a single target platform.

:pencil2: _NOTE: Some generators may silently ignore optional keyword tokens which they do not support._

:warning: _WARNING: When developing filters that are intended to be rendered across multiple generators (cisco, iptables & Juniper for example) it is strongly recommended to only use required keyword tokens in the policy terms. This will help ensure each platform's rendered filter will contain compatible security policies._

# Keywords
The following are a list of keywords that must be supported by all output generators:

|Keyword|Description|Possible Values|
|---|---|---|
|`action::`|The action to take when matched.| `[accept|deny|reject|next|reject-with-tcp-rst]`|
|`comment::`|A text comment enclosed in double-quotes. The comment can extend over multiple lines if desired, until a closing quote is encountered.||
|`destination-address::`|One or more destination address tokens.||
|`destination-exclude::`|Exclude one or more address tokens from the  specified destination-address| |
|`destination-port::` | One or more service definition tokens.||
|`icmp-type::`|Specify icmp-type code to match, see section [ICMP TYPES](#ICMP_TYPES) for list of valid arguments.| |
|`option::` | See section [TCP OPTIONS](#TCP_OPTIONS) for details. |`[established|tcp-established|sample|intial|rst|first-fragment]`|
|`protocol::`|The network protocols this term will match, such as tcp, udp, icmp, or a numeric value.|`[tcp|udp|icmp|94]`|
|`protocol-except::`|Network protocols that should be excluded from the protocol specification. This is rarely used.| |
|`source-address::`|One or more source address tokens. | |
|`source-exclude::`|Exclude one or more address tokens from the specified source-address. | |
|`source-port::` |One or more service definition tokens. | |
|`verbatim::`|This specifies that the text enclosed within quotes should be rendered into the output without interpretation or modification. This is sometimes used as a temporary workaround while new required features are being added.| |

# Optionally Supported Keywords
The following are keywords that can be optionally supported by output generators. It is important to note that these may or may not function properly on all generators.

|Keyword|Description|Possible values|
|---|---|---|
|`address::`|One or more network address tokens.||
|`counter::`|Juniper only, update a counter for matching packets.||
|`destination-prefix::`|Juniper only, specify destination-prefix matching (e.g. source-prefix:: configured-neighbors-only).||
|`ether-type::`|Juniper only, specify matching ether-type (e.g. `ether-type:: arp`)|
|`fragement-offset::`|Juniper only, specify a fragment offset of a fragmented packet||
|`logging::`|Supported Juniper and iptables/speedway, specify that this packet should be logged via syslog||
|`loss-priority::`|Juniper only, specify loss priority||
|`packet-length::`|Juniper only, specify packet length||
|`policer::`|Juniper only, specify which policer to apply to matching packets||
|`precedence::`|Juniper only, specify precendence||
|`qos::`|Juniper only, apply quality of service classification to matching packets (e.g. qos:: af4)||
|`routing-instance::`|Juniper only, specify routing instance for matching packets||
|`source-interface::`|iptables and speedway only, specify specific interface a term should apply to (e.g. source-interface:: eth3)||
|`source-prefix::`|Juniper only, specify source-prefix matching (e.g. source-prefix:: configured-neighbors-only)||
|`traffic-type::`|Juniper only, specify traffic-type||

# Term Examples
The following are examples of how to construct a term, and assumes that naming definition tokens used have been defined in the definitions files.

* Block incoming bogons and spoofed traffic

  ```
  term block-bogons {
    source-address:: BOGONS RFC1918
    source-address:: COMPANY_INTERNAL
    action:: deny
  ```

* Permit Public to Web Servers

  ```
  term permit-to-web-servers {
    destination-address:: WEB_SERVERS
    destination-port:: HTTP
    protocol:: tcp
    action:: accept
  }
  ```

* Permit Replies to DNS Servers From Primaries

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

* Permit All Corporate Networks, Except New York, to FTP Server

  :pencil2: _This will "subtract" the `CORP_NYC_NETBLOCK` from the `CORP_NETBLOCKS` token. For example, assume `CORP_NETBLOCKS` includes 200.0.0.0/20, and `CORP_NYC_NETBLOCK` is defined as 200.2.0.0/24. The source-exclude will remove the `NYC` netblock from the permitted source addresses. If the excluded address is not contained with the source address, nothing is changed._

  ```
  term allow-inbound-ftp-from-corp {
    source-address:: CORP_NETBLOCKS
    source-exclude:: CORP_NYC_NETBLOCK
    destination-port:: FTP
    protocol:: tcp
    action:: accept
  }
  ```

# Includes
The policy language supports the use of #include statements. An include can be used to avoid duplication of commonly used text, such as a group of terms that permit or block specific types of traffic.

An include directive will result in the contents of the included file being injected into the current policy at the exact location of the include directive.

The include directive has the following format:

```
#include 'policies/includes/untrusted-networks-blocking.inc'
```

The .inc file extension and `includes/` directory path are not required, but typically used to help differentiate from typical policy files.

# Example Policy File

Below is an example policy file for a Juniper target platform. It contains two filters, each with a handful of terms. This examples assumes that the network and service naming definition tokens have been defined.

```
header {
  comment:: "edge input filter for sample network."
  target:: Juniper edge-inbound
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
  target:: Juniper edge-outbound
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

# ICMP TYPES <a name="ICMP_TYPES"></a>
The following are the list of icmp-type specifications which can be used with the `icmp-type::` policy token.

IPv4

```
echo-reply
unreachable
source-quench
redirect
alternate-address
echo-request
router-advertisement
router-solicitation
time-exceeded
parameter-problem
timestamp-request
timestamp-reply
information-request
information-reply
mask-request
mask-reply
conversion-error
mobile-redirect
```

IPv6

```
destination-unreachable
packet-too-big
time-exceeded
parameter-problem
echo-request
echo-reply
multicast-listener-query
multicast-listener-report
multicast-listener-done
router-solicit
router-advertisement
neighbor-solicit
neighbor-advertisement
redirect-message
router-renumbering
icmp-node-information-query
icmp-node-information-response
inverse-neighbor-discovery-solicitation
inverse-neighbor-discovery-advertisement
version-2-multicast-listener-report
home-agent-address-discovery-request
home-agent-address-discovery-reply
mobile-prefix-solicitation
mobile-prefix-advertisement
certification-path-solicitation
certification-path-advertisement
multicast-router-advertisement
multicast-router-solicitation
multicast-router-termination
```

# TCP OPTIONS <a name="TCP_OPTIONS"></a>
The following are the list of TCP option specifications which can be used with the `option::` policy token.

* **established** - only permit established connections, implements tcp-established if protocol is tcp only, otherwise adds 1024-65535 to required destination-ports.
* **tcp-established** - only permit established tcp connections, usually checked based on TCP flag settings. If protocol UDP is included in term, only adds 1024-65535 to required destination-ports.
* **sample** - not supported by all generators. Samples traffic for netflow.
* **initial** - currently only supported by Juniper generator. Appends `tcp-initial` to the term.
* **rst** - currently only supported by Juniper generator. Appends `tcp-flags rst` to the term.
* **first-fragment** - currently only supported by Juniper generator. Appends `first-fragment` to the term.

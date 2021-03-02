# iptables

NOTE: Iptables produces output that must be passed, line by line, to the 'iptables/ip6tables' command line. For 'iptables-restore' compatible output, please use the Speedway generator.

The Iptables header designation has the following format:

```
target:: iptables [INPUT|OUTPUT|FORWARD|custom] {ACCEPT|DROP} {truncatenames} {nostate} {inet|inet6}
INPUT: apply the terms to the input filter.
OUTPUT: apply the terms to the output filter.
FORWARD: apply the terms to the forwarding filter.
custom: create the terms under a custom filter name, which must then be linked/jumped to from one of the default filters (e.g. iptables -A input -j custom)
ACCEPT: specifies that the default policy on the filter should be 'accept'.
DROP: specifies that the default policy on the filter should be to 'drop'.
inet: specifies that the resulting filter should only render IPv4 addresses.
inet6: specifies that the resulting filter should only render IPv6 addresses.
truncatenames: specifies to abbreviate term names if necessary (see lib/iptables.py:CheckTerMLength for abbreviation table)
nostate: specifies to produce 'stateless' filter output (e.g. no connection tracking)
```

## Iptables
NOTE: Iptables produces output that must be passed, line by line, to the 'iptables/ip6tables' command line.  For 'iptables-restore' compatible output, please use the [Speedway](PolicyFormat#Speedway.md) generator.
The Iptables header designation has the following format:
```
target:: iptables [INPUT|OUTPUT|FORWARD|custom] {ACCEPT|DROP} {truncatenames} {nostate} {inet|inet6}
```
  * _INPUT_: apply the terms to the input filter.
  * _OUTPUT_: apply the terms to the output filter.
  * _FORWARD_: apply the terms to the forwarding filter.
  * _custom_: create the terms under a custom filter name, which must then be linked/jumped to from one of the default filters (e.g. iptables -A input -j custom)
  * _ACCEPT_: specifies that the default policy on the filter should be 'accept'.
  * _DROP_: specifies that the default policy on the filter should be to 'drop'.
  * _inet_: specifies that the resulting filter should only render IPv4 addresses.
  * _inet6_: specifies that the resulting filter should only render IPv6 addresses.
  * _truncatenames_: specifies to abbreviate term names if necessary (see lib/iptables.py:_CheckTerMLength for abbreviation table)
  *_nostate_: specifies to produce 'stateless' filter output (e.g. no connection tracking)_
## Term Format
* _action::_ The action to take when matched. See Actions section for valid options.
* _comment::_ A text comment enclosed in double-quotes.  The comment can extend over multiple lines if desired, until a closing quote is encountered.
* _counter::_ Update a counter for matching packets
* _destination-address::_ One or more destination address tokens
* _destination-exclude::_ Exclude one or more address tokens from the specified destination-address
* _destination-interface::_ Specify specific interface a term should apply to (e.g. destination-interface:: eth3)
* _destination-port::_ One or more service definition tokens
* _destination-prefix::_ Specify destination-prefix matching (e.g. source-prefix:: configured-neighbors-only)
* _expiration::_ stop rendering this term after specified date. [YYYY](YYYY.md)-[MM](MM.md)-[DD](DD.md)
* _fragement-offset::_ specify a fragment offset of a fragmented packet
* _icmp-code::_ Specifies the ICMP code to filter on.
* _icmp-type::_ Specify icmp-type code to match, see section [ICMP TYPES](PolicyFormat#ICMP_TYPES.md) for list of valid arguments
* _logging::_ Specify that this packet should be logged via syslog.
* _name::_ Name of the term.
* _option::_ See platforms supported Options section.
* _owner::_ Owner of the term, used for organizational purposes.
* _packet-length::_ specify packet length.
* _platform::_ one or more target platforms for which this term should ONLY be rendered.
*_platform-exclude:: one or more target platforms for which this term should NEVER be rendered.
* _protocol::_ the network protocols this term will match, such as tcp, udp, icmp, or a numeric value.
* _routing-instance::_ specify routing instance for matching packets.
* _source-address::_ one or more source address tokens.
* _source-exclude::_ exclude one or more address tokens from the specified source-address.
* _source-interface::_ specify specific interface a term should apply to (e.g. source-interface:: eth3).
* _source-port::_ one or more service definition tokens.
* _source-prefix::_ specify source-prefix matching (e.g. source-prefix:: configured-neighbors-only).
* _verbatim::_ this specifies that the text enclosed within quotes should be rendered into the output without interpretation or modification.  This is sometimes used as a temporary workaround while new required features are being added.
## Sub Tokens
### Actions
* _accept_
* _deny_
* _next_
* _reject_
* _reject-with-tcp-rst_

### Option

* _ack::_ Match on ACK flag being present.
* _all::_ Matches all protocols.
* _established::_ Only match established connections, implements tcp-established for tcp and sets destination port to 1024- 65535 for udp if destination port is not defined.
* _fin::_ Match on FIN flag being present.
* _first-fragment::_ Only match on first fragment of a fragmented pakcet.
* _initial::_ Only matches on initial packet.
* _is-fragment::_ Matches on if a packet is a fragment.
* _none::_ Matches none.
* _psh::_ Match on PSH flag being present.
* _rst::_ Match on RST flag being present.
* _sample::_ Samples traffic for netflow.
* _syn::_ Match on SYN flag being present.
* _tcp-established::_ Only match established tcp connections, based on statefull match or TCP flags. Not supported for other protocols.
* _tcp-initial::_ Only match initial packet for TCP protocol.
* _urg::_ Match on URG flag being present.

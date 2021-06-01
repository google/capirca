# Ipset

Ipset is a system inside the Linux kernel, which can very efficiently store and match IPv4 and IPv6 addresses. This can be used to dramatically increase performance of iptables firewall.
The Ipset header designation follows the Iptables format above, but uses the target platform of 'ipset':

```
target:: ipset [INPUT|OUTPUT|FORWARD|custom] {ACCEPT|DROP} {truncatenames} {nostate} {inet|inet6}
```

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


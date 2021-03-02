# Juniper

The juniper header designation has the following format:

```
target:: juniper [filter name] {inet|inet6|bridge}
filter name: defines the name of the juniper filter.
inet: specifies the output should be for IPv4 only filters. This is the default format.
inet6: specifies the output be for IPv6 only filters.
bridge: specifies the output should render a Juniper bridge filter.
```

When inet4 or inet6 is specified, naming tokens with both IPv4 and IPv6 filters
will be rendered using only the specified addresses.

The default format is `inet4`, and is implied if not other argument is given.



## Juniper
The juniper header designation has the following format:
```
target:: juniper [filter name] {inet|inet6|bridge} {dsmo} {not-interface-specific}
```
  * _filter name_: defines the name of the juniper filter.
  * _inet_: specifies the output should be for IPv4 only filters. This is the default format.
  * _inet6_: specifies the output be for IPv6 only filters.
  * _bridge_: specifies the output should render a Juniper bridge filter.
  * _dsmo_: Enable discontinuous subnet mask summarization.
  * _not-interface-specific_: Toggles "interface-specific" inside of a term.
When _inet4_ or _inet6_ is specified, naming tokens with both IPv4 and IPv6 filters will be rendered using only the specified addresses.
The default format is _inet4_, and is implied if not other argument is given.
## Term Format
* _action::_ The action to take when matched. See Actions section for valid options.
* _address::_ One or more network address tokens, matches source or destination.
* _comment::_ A text comment enclosed in double-quotes.  The comment can extend over multiple lines if desired, until a closing quote is encountered.
* _counter::_ Update a counter for matching packets
* _destination-address::_ One or more destination address tokens
* _destination-exclude::_ Exclude one or more address tokens from the specified destination-address
* _destination-port::_ One or more service definition tokens
* _destination-prefix::_ Specify destination-prefix matching (e.g. source-prefix:: configured-neighbors-only)
* _destination-prefix_except::_ Specify destination-prefix exception(TODO:cmas Fill in more).
* _dscp_except::_ Do not match the DSCP number.
* _dscp_match::_ Match a DSCP number.
* _dscp_set::_ Match a DSCP set.
* _ether_type::_ Match EtherType field.
* _expiration::_ stop rendering this term after specified date. [YYYY](YYYY.md)-[MM](MM.md)-[DD](DD.md)
* _flexible-match-range Filter based on flexible match options.
* _forwarding-class::_ Specify the forwarding class to match.
* _forwarding-class_except::_ Do not match the specified forwarding classes.
* _fragement-offset::_ specify a fragment offset of a fragmented packet
* _hop-limit::_ Match the hop limit to the specified hop limit or set of hop limits.
* _icmp-code::_ Specifies the ICMP code to filter on.
* _icmp-type::_ Specify icmp-type code to match, see section [ICMP TYPES](PolicyFormat#ICMP_TYPES.md) for list of valid arguments
* _logging::_ Specify that this packet should be logged via syslog.
* _loss-priority::_ Specify loss priority.
* _name::_ Name of the term.
* _next-ip::_ Used in filter based forwarding.
* _option::_ See platforms supported Options section.
* _owner::_ Owner of the term, used for organizational purposes.
* _packet-length::_ specify packet length.
* _platform::_ one or more target platforms for which this term should ONLY be rendered.
*_platform-exclude:: one or more target platforms for which this term should NEVER be rendered.
* _policer::_ specify which policer to apply to matching packets.
* _port::_ Matches on source or destination ports. Takes a service token.
* _precedence::_ specify precedence of range 0-7.  May be a single integer, or a space separated list.
* _protocol::_ the network protocols this term will match, such as tcp, udp, icmp, or a numeric value.
* _protocol\_except::_ allow all protocol "except" specified.
* _qos::_ apply quality of service classification to matching packets (e.g. qos:: af4)
* _routing-instance::_ specify routing instance for matching packets.
* _source-address::_ one or more source address tokens.
* _source-exclude::_ exclude one or more address tokens from the specified source-address.
* _source-port::_ one or more service definition tokens.
* _source-prefix::_ specify source-prefix matching (e.g. source-prefix:: configured-neighbors-only).
* _source-prefix-except::_ specify destination-prefix exception(TODO:cmas Fill in more).
* _traffic-class-count::_
* _traffic-type::_ specify traffic-type
* _ttl::_ Matches on TTL.
* _verbatim::_ this specifies that the text enclosed within quotes should be rendered into the output without interpretation or modification.  This is sometimes used as a temporary workaround while new required features are being added.
## Sub Tokens
### Actions
* _accept_
* _deny_
* _next_
* _reject_
* _reject-with-tcp-rst_
### Option
* _.*::_ wat
* _established::_ Only match established connections, implements tcp-established for tcp and sets destination port to 1024- 65535 for udp if destination port is not defined.
* _first-fragment::_ Only match on first fragment of a fragmented pakcet.
* _sample::_ Samples traffic for netflow.
* _tcp-established::_ Only match established tcp connections, based on statefull match or TCP flags. Not supported for other protocols.
* _tcp-initial::_ Only match initial packet for TCP protocol.


# Cisco

The cisco header designation has the following format:
```
target:: cisco [filter name] {extended|standard|object-group|inet6|mixed} {dsmo}
```
  * _filter name_: defines the name or number of the cisco filter.
  * _extended_: specifies that the output should be an extended access list, and the filter name should be non-numeric.  This is the default option.
  * _standard_: specifies that the output should be a standard access list, and the filter name should be numeric and in the range of 1-99.
  * _object-group_: specifies this is a cisco extended access list, and that object-groups should be used for ports and addresses.
  * _inet6_: specifies the output be for IPv6 only filters.
  * _mixed_: specifies output will include both IPv6 and IPv4 filters.
  * _dsmo_: Enable discontinuous subnet mask summarization.
When _inet4_ or _inet6_ is specified, naming tokens with both IPv4 and IPv6 filters will be rendered using only the specified addresses.
The default format is _inet4_, and is implied if not other argument is given.

## Term Format
* _action::_ The action to take when matched. See Actions section for valid options.
* _address::_ One or more network address tokens, matches source or destination.
* _comment::_ A text comment enclosed in double-quotes.  The comment can extend over multiple lines if desired, until a closing quote is encountered.
* _destination-address::_ One or more destination address tokens
* _destination-exclude::_ Exclude one or more address tokens from the specified destination-address
* _destination-port::_ One or more service definition tokens
* _dscp_match::_ Match a DSCP number.
* _expiration::_ stop rendering this term after specified date. [YYYY](YYYY.md)-[MM](MM.md)-[DD](DD.md)
* _icmp-code::_ Specifies the ICMP code to filter on.
* _icmp-type::_ Specify icmp-type code to match, see section [ICMP TYPES](PolicyFormat#ICMP_TYPES.md) for list of valid arguments
* _logging::_ Specify that this packet should be logged via syslog.
* _name::_ Name of the term.
* _option::_ See platforms supported Options section.
* _owner::_ Owner of the term, used for organizational purposes.
* _platform::_ one or more target platforms for which this term should ONLY be rendered.
*_platform-exclude:: one or more target platforms for which this term should NEVER be rendered.
* _protocol::_ the network protocols this term will match, such as tcp, udp, icmp, or a numeric value.
* _source-address::_ one or more source address tokens.
* _source-exclude::_ exclude one or more address tokens from the specified source-address.
* _source-port::_ one or more service definition tokens.
* _verbatim::_ this specifies that the text enclosed within quotes should be rendered into the output without interpretation or modification.  This is sometimes used as a temporary workaround while new required features are being added.

## Sub Tokens

### Actions
* _accept_
* _deny_
* _next_
* _reject_
* _reject-with-tcp-rst_

### Option

* _established::_ Only match established connections, implements tcp-established for tcp and sets destination port to 1024- 65535 for udp if destination port is not defined.
* _is-fragment::_ Matches on if a packet is a fragment.
* _tcp-established::_ Only match established tcp connections, based on statefull match or TCP flags. Not supported for other protocols.
* _tcp-initial::_ Only match initial packet for TCP protocol.

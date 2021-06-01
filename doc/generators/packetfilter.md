# PacketFilter

Note: The PF generator is currently in alpha testing. The output should be compatible with OpenBSD v4.7 PF and later.

```
target:: packetfilter {inet|inet6|mixed}
```
  * _inet_: specifies that the resulting filter should only render IPv4 addresses.
  * _inet6_: specifies that the resulting filter should only render IPv6 addresses.
  * _mixed_: specifies that the resulting filter should only render IPv4 and IPv6 addresses (default).
## Term Format
* _action::_ The action to take when matched. See Actions section for valid options.
* _comment::_ A text comment enclosed in double-quotes.  The comment can extend over multiple lines if desired, until a closing quote is encountered.
* _destination-address::_ One or more destination address tokens
* _destination-exclude::_ Exclude one or more address tokens from the specified destination-address
* _destination-port::_ One or more service definition tokens
* _expiration::_ stop rendering this term after specified date. [YYYY](YYYY.md)-[MM](MM.md)-[DD](DD.md)
* _icmp-type::_ Specify icmp-type code to match, see section [ICMP TYPES](PolicyFormat#ICMP_TYPES.md) for list of valid arguments
* _logging::_ Specify that this packet should be logged via syslog.
* _name::_ Name of the term.
* _option::_ See platforms supported Options section.
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
### Option
* _ack::_ Match on ACK flag being present.
* _all::_ Matches all protocols.
* _established::_ Only match established connections, implements tcp-established for tcp and sets destination port to 1024- 65535 for udp if destination port is not defined.
* _fin::_ Match on FIN flag being present.
* _is-fragment::_ Matches on if a packet is a fragment.
* _psh::_ Match on PSH flag being present.
* _rst::_ Match on RST flag being present.
* _syn::_ Match on SYN flag being present.
* _tcp-established::_ Only match established tcp connections, based on statefull match or TCP flags. Not supported for other protocols.
* _urg::_ Match on URG flag being present.

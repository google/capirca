# nftables

The NFTables header designation has the following format:
```
target:: nftables [chain name] [filter name] [priority] [inet|inet6]
```
  * _chain name_: defines the name of the nftables chain.
  * _filter name_: defines the name of the nftables filter.
  * _priority_: defines the integer of the nftables chain priority.
  * _inet_: specifies that the resulting filter should only render IPv4 addresses.
  * _inet6_: specifies that the resulting filter should only render IPv6 addresses.
NOTE: all of these fields are required.
## Term Format
* _action::_ The action to take when matched. See Actions section for valid options.
* _comment::_ A text comment enclosed in double-quotes.  The comment can extend over multiple lines if desired, until a closing quote is encountered.
* _counter::_ Update a counter for matching packets
* _destination-address::_ One or more destination address tokens
* _destination-exclude::_ Exclude one or more address tokens from the specified destination-address
* _destination-port::_ One or more service definition tokens
* _expiration::_ stop rendering this term after specified date. [YYYY](YYYY.md)-[MM](MM.md)-[DD](DD.md)
* _icmp-type::_ Specify icmp-type code to match, see section [ICMP TYPES](PolicyFormat#ICMP_TYPES.md) for list of valid arguments
* _log-name::_ Name of log to log to.
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

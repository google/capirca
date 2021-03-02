# WindowsAdvFirewall
The Windows Advanced Firewall header designation has the following format:
```
target:: windows_advfirewall {out|in} {inet|inet6|mixed}
```
  * _out_: Specifies that the direction of packet flow is out. (default)
  * _in_: Specifies that the direction of packet flow is in.
  * _inet_: specifies that the resulting filter should only render IPv4 addresses.
  * _inet6_: specifies that the resulting filter should only render IPv6 addresses.
## Term Format
* _action::_ The action to take when matched. See Actions section for valid options.
* _comment::_ A text comment enclosed in double-quotes.  The comment can extend over multiple lines if desired, until a closing quote is encountered.
* _destination-address::_ One or more destination address tokens
* _destination-exclude::_ Exclude one or more address tokens from the specified destination-address
* _destination-port::_ One or more service definition tokens
* _expiration::_ stop rendering this term after specified date. [YYYY](YYYY.md)-[MM](MM.md)-[DD](DD.md)
* _icmp-type::_ Specify icmp-type code to match, see section [ICMP TYPES](PolicyFormat#ICMP_TYPES.md) for list of valid arguments
* _name::_ Name of the term.
* _option::_ See platforms supported Options section.
* _platform::_ one or more target platforms for which this term should ONLY be rendered.
*_platform-exclude:: one or more target platforms for which this term should NEVER be rendered.
* _protocol::_ the network protocols this term will match, such as tcp, udp, icmp, or a numeric value.
* _source-address::_ one or more source address tokens.
* _source-exclude::_ exclude one or more address tokens from the specified source-address.
* _source-port::_ one or more service definition tokens.
## Sub Tokens
### Actions
* _accept_
* _deny_

## WindowsIPSec
The Windows IPSec header designation has the following format:
```
target:: windows_advfirewall [filter_name]
```
  * _filter name_: defines the name of the Windows IPSec filter.
## Term Format
* _action::_ The action to take when matched. See Actions section for valid options.
* _comment::_ A text comment enclosed in double-quotes.  The comment can extend over multiple lines if desired, until a closing quote is encountered.
* _destination-address::_ One or more destination address tokens
* _destination-exclude::_ Exclude one or more address tokens from the specified destination-address
* _destination-port::_ One or more service definition tokens
* _expiration::_ stop rendering this term after specified date. [YYYY](YYYY.md)-[MM](MM.md)-[DD](DD.md)
* _name::_ Name of the term.
* _option::_ See platforms supported Options section.
* _platform::_ one or more target platforms for which this term should ONLY be rendered.
*_platform-exclude:: one or more target platforms for which this term should NEVER be rendered.
* _protocol::_ the network protocols this term will match, such as tcp, udp, icmp, or a numeric value.
* _source-address::_ one or more source address tokens.
* _source-exclude::_ exclude one or more address tokens from the specified source-address.
* _source-port::_ one or more service definition tokens.
## Sub Tokens
### Actions
* _accept_
* _deny_

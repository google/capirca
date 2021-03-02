# Aruba

The aruba header designation has the following format:
```
target:: aruba [filter name] {ipv6}
```
  * _filter name_: defines the name of the arista filter.
  * _ipv6_: specifies the output be for IPv6 only filters.

## Term Format
* _action::_ The action to take when matched. See Actions section for valid options.
* _comment::_ A text comment enclosed in double-quotes.  The comment can extend over multiple lines if desired, until a closing quote is encountered.
* _destination-address::_ One or more destination address tokens
* _destination-port::_ One or more service definition tokens
* _expiration::_ stop rendering this term after specified date. [YYYY](YYYY.md)-[MM](MM.md)-[DD](DD.md)
* _name::_ Name of the term.
* _option::_ See platforms supported Options section.
* _protocol::_ the network protocols this term will match, such as tcp, udp, icmp, or a numeric value.
* _source-address::_ one or more source address tokens.
* _verbatim::_ this specifies that the text enclosed within quotes should be rendered into the output without interpretation or modification.  This is sometimes used as a temporary workaround while new required features are being added.
## Sub Tokens
### Actions
* _accept_
* _deny_
### Option
* _destination-is-user::_ Aruba option to specify that the destination should be a user.
* _negate::_ Used with DSM summarizer, negates the DSM.
* _source-is-user::_ Aruba option to specify that the source should be a user.

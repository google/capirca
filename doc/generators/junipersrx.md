
## JuniperSRX
Note: The Juniper SRX generator is currently in beta testing.
```
target:: srx from-zone [zone name] to-zone [zone name] {inet}
```
  * _from-zone_: static keyword, followed by user specified zone
  * _to-zone_: static keyword, followed by user specified zone
  * _inet_: Address family (only IPv4 tested at this time)
### Term Format
* _action::_ The action to take when matched. See Actions section for valid options.
* _comment::_ A text comment enclosed in double-quotes.  The comment can extend over multiple lines if desired, until a closing quote is encountered.
* _destination-address::_ One or more destination address tokens
* _destination-exclude::_ Exclude one or more address tokens from the specified destination-address
* _destination-port::_ One or more service definition tokens
* _destination-zone::_ one or more destination zones tokens. Only supported by global policy
* _dscp_except::_ Do not match the DSCP number.
* _dscp_match::_ Match a DSCP number.
* _dscp_set::_ Match a DSCP set.
* _expiration::_ stop rendering this term after specified date. [YYYY](YYYY.md)-[MM](MM.md)-[DD](DD.md)
* _icmp-type::_ Specify icmp-type code to match, see section [ICMP TYPES](PolicyFormat#ICMP_TYPES.md) for list of valid arguments
* _logging::_ Specify that these packets should be logged.
  * Based on the input value the resulting logging actions will follow this logic:
    * _action_ is 'accept':
      * _logging_ is 'true': resulting SRX output will be 'log { session-close; }'
      * _logging_ is 'log-both': resulting SRX output will be 'log { session-init; session-close; }'
    * _action_ is 'deny':
      * _logging_ is 'true': resulting SRX output will be 'log { session-init; }'
      * _logging_ is 'log-both': resulting SRX output will be 'log { session-init; session-close; }'
    * See [here](https://kb.juniper.net/InfoCenter/index?page=content&id=KB16506) for explanation.
* _name::_ Name of the term.
* _option::_ See platforms supported Options section.
* _owner::_ Owner of the term, used for organizational purposes.
* _platform::_ one or more target platforms for which this term should ONLY be rendered.
*_platform-exclude:: one or more target platforms for which this term should NEVER be rendered.
* _protocol::_ the network protocols this term will match, such as tcp, udp, icmp, or a numeric value.
* _source-address::_ one or more source address tokens.
* _source-exclude::_ exclude one or more address tokens from the specified source-address.
* _source-port::_ one or more service definition tokens.
* _source-zone::_ one or more source zones tokens. Only supported by global policy
* _timeout::_ specify application timeout. (default 60)
* _verbatim::_ this specifies that the text enclosed within quotes should be rendered into the output without interpretation or modification.  This is sometimes used as a temporary workaround while new required features are being added.
* _vpn::_ Encapsulate outgoing IP packets and decapsulate incomfing IP packets.
### Sub Tokens
#### Actions
* _accept_
* _count_
* _deny_
* _dscp_
* _log_
* _reject_


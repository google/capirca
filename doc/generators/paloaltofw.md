# PaloAltoFW

```
target:: paloalto from-zone [zone name] to-zone [zone name]
```
  * _from-zone: static keyword, followed by user specified zone
  * _to-zone: static keyword, followed by user specified zone
Terms Section
Optionally Supported Keywords
  * _pan-application:: paloalto only, specify a Palo Alto application.
The application needs to already be existing on the device.
If an "application" is defined, but no "service", service will default to "application-default".
## Term Format
* _action::_ The action to take when matched. See Actions section for valid options.
* _comment::_ A text comment enclosed in double-quotes.  The comment can extend over multiple lines if desired, until a closing quote is encountered.
* _destination-address::_ One or more destination address tokens
* _destination-port::_ One or more service definition tokens
* _expiration::_ stop rendering this term after specified date. [YYYY](YYYY.md)-[MM](MM.md)-[DD](DD.md)
* _icmp-type::_ Specify icmp-type code to match, see section [ICMP TYPES](PolicyFormat#ICMP_TYPES.md) for list of valid arguments
* _logging::_ Specify that this packet should be logged via syslog.
* _name::_ Name of the term.
* _owner::_ Owner of the term, used for organizational purposes.
* _pan-application::_ Specify a Palo Alto application. Application must be defined on device.
* _platform::_ one or more target platforms for which this term should ONLY be rendered.
* _protocol::_ the network protocols this term will match, such as tcp, udp, icmp, or a numeric value.
* _source-address::_ one or more source address tokens.
* _source-port::_ one or more service definition tokens.
* _timeout::_ specify application timeout. (default 60)
## Sub Tokens
### Actions
* _accept_
* _count_
* _deny_
* _log_
* _reject_

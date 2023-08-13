
## Versa
Note: The Versa  generator is currently in beta testing.
```
target:: srx from-zone [zone name] to-zone [zone name] {template templatename } {tenant tenantname}  {policy policyname} { inet} 
```
  * _from-zone_: static keyword, followed by user specified zone
  * _to-zone_: static keyword, followed by user specified zone
  * _template_: static keyword, followed by user specified template name 
  * _tenant_: static keyword, followed by user specified tenant name 
  * _policy: static keyword, followed by user specified policy name 
  * _inet_: Address family (only IPv4 tested at this time)
  
### Term Format
* _action::_ The action to take when matched. See Actions section for valid options.
* _comment::_ A text comment enclosed in double-quotes.  The comment can extend over multiple lines if desired, until a closing quote is encountered.
* _destination-address::_ One or more destination address tokens
* _destination-exclude::_ Exclude one or more address tokens from the specified destination-address
* _destination-port::_ One or more service definition tokens
* _destination-zone::_ one or more destination zones tokens. Only supported by global policy
* _dscp_match::_ Match a DSCP number.
* _logging::_ Specify that these packets should be logged.
  * Based on the input value the resulting logging actions will follow this logic:
    * _action_ is 'accept':
      * _logging_ is 'true': resulting output will be 'event start;'
      * _logging_ is 'log-both': resulting output will be 'event both;'
* _name::_ Name of the term.
* _option::_ See platforms supported Options section.
* _owner::_ Owner of the term, used for organizational purposes.
* _platform::_ one or more target platforms for which this term should ONLY be rendered.
* _protocol::_ the network protocols this term will match, such as tcp, udp, icmp, or a numeric value.
* _source-address::_ one or more source address tokens.
* _source-exclude::_ exclude one or more address tokens from the specified source-address.
* _source-port::_ one or more service definition tokens.
* _source-zone::_ one or more source zones tokens. Only supported by global policy
### Sub Tokens
#### Actions
* _accept_
* _deny_
* _dscp_
* _log_
* _reject_


# NSXT

The nsx header designation has the following format:

```
target:: nsxt {section_name} {inet|inet6|mixed} section-id securitygroup securitygroupId
section_name: specifies the name of the section all terms in this header apply to.
inet: specifies that the resulting filter should only render IPv4 addresses.
inet6: specifies that the resulting filter should only render IPv6 addresses.
mixed: specifies that the resulting filter should render both IPv4 and IPv6 addresses.
sectionId: specifies the Id for the section [optional]
securitygroup: specifies that the appliedTo should be security group [optional]
securitygroupId: specifies the Id of the security group [mandatory if securitygroup is given]
(Required keywords option and verbatim are not supported in NSX)
```


## Nsxt
The nsxt header designation has the following format:
```
target:: nsxt {section_name} {inet|inet6|mixed} section-id securitygroup securitygroupId
```
  * _section_name_: specifies the name of the dfw rule all terms in this header apply to. [mandatory field]
  * _inet_: specifies the output should be for IPv4 only filters. This is the default format.
  * _inet6_: specifies the output be for IPv6 only filters.
  * _mixed_: specifies that the resulting filter should render both IPv4 and IPv6 addresses.
  * _sectionId_: specifies the Id for the section [optional]
  * _securitygroup_: specifies that the appliedTo should be security group [optional]
  * _securitygroupId_: specifies the Id of the security group [mandatory if securitygroup is given]
(Required keywords option and verbatim are not supported in NSX)
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
* _reject_
* _reject-with-tcp-rst_

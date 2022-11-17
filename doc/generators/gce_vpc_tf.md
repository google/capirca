# Terraform GCE

The Terraform GCE header designation has the following format:

```
target:: gce_vpc_tf [filter name] [network name] [direction] [max policy cost]
```

* _filter name_: defines the name of the gce_vpc_tf filter.
* _network name_: defines the name of the network the filter applies to.
* _direction_: defines the direction, valid inputs are INGRESS and EGRESS (default:INGRESS)
* _max policy cost_: maximum policy cost as an integer.

## Term Format

* _action::_ The action to take when matched. See Actions section for valid options.
* _comment::_ A text comment enclosed in double-quotes.  The comment can extend over multiple lines if desired, until a closing quote is encountered.
* _destination-address::_ One or more destination address tokens
* _destination-exclude::_ Exclude one or more address tokens from the specified destination-address
* _destination-port::_ One or more service definition tokens
* _destination_tag::_ Tag name to be used for destination filtering.
* _expiration::_ stop rendering this term after specified date. [YYYY](YYYY.md)-[MM](MM.md)-[DD](DD.md)
* _name::_ Name of the term.
* _option::_ See platforms supported Options section.
* _owner::_ Owner of the term, used for organizational purposes.
* _priority_ Relative priority of rules when evaluated on the platform.
* _protocol::_ the network protocols this term will match, such as tcp, udp, icmp, or a numeric value.
* _source-address::_ one or more source address tokens.
* _source-exclude::_ exclude one or more address tokens from the specified source-address.
* _source-port::_ one or more service definition tokens.
* _source-service-accounts::_ A service account that the term applies to.
* _source-tag::_ Tag name used for source filtering.
* _target-service-accounts::_ A service account that the term applies to.  For ingress rules it is the destination, for egress rules it is the source.

## Sub Tokens

### Actions

* _accept_
* _deny_

# SONiC

The SONiC header designation has the following format:

```
target:: sonic filter-name {inet|inet6|mixed}
```

* _filter-name_: defines the name of the filter. This is a required field.
  Note that the filter name will be present as a key of every ACE (i.e. rule) in
  generated policy. For example if the filter-name is 'MyPolicy', each ACE will
  come out like:

  ```
  {
    'ACL_RULE': {
      'MyPolicy|RULE_10': {...},
      'MyPolicy|RULE_20': {...},
      ...
    }
  }
  ```

## Term Format

* _action::_ The action to take when matched. See Actions section for valid
  options.
* _destination-address::_ One or more destination address tokens.
* _destination-port::_ One or more service definition tokens.
* _expiration::_ Stop rendering this term after specified date. Date format:
  [YYYY](YYYY.md)-[MM](MM.md)-[DD](DD.md).
* _protocol::_ The network protocols this term will match, such as tcp, udp, or
  sctp.
* _source-address::_ One or more source address tokens.
* _source-port::_ One or more service definition tokens.

## Sub Tokens

### Actions

* _accept_
* _deny_

### Option

* _tcp-established::_ Only match "established" connections. It is not stateful -
  any TCP packet with ACK and/or RST TCP flag set will match.

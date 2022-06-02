# Nftables

This file will be updated as functionality extends and may be useful for reference during code reviews.

The NFTables header designation has the following format:

```
target:: newnftables [nf_address_family] [nf_hook] {default_policy_override} {int: base chain priority} {noverbose}
```

Unless otherwise stated, all fields are required unless they're marked optional.

- nf_address_family: defines the IP address family for the policies. (inet, inet6, mixed)
- nf_hook: defines the traffic direction and the nftables hook for the rules. (input, output)
- default_policy_override: **OPTIONAL** defines the default action (ACCEPT, DROP) for non-matching packets. Default behavior is DROP.
- priority: **OPTIONAL** By default, this generator creates base chains with a starting priority of 0. Defining an integer value will override this behavior.
- noverbose: **OPTIONAL** Disable header and term comments in final ACL output. Default behavior is verbose.

#### Reporting bugs

When reporting bugs about this generator ensure to include:
1.  Example policy (.pol file)
1.  Observed output (.nft file)
1.  Expected (correct) output in Nftables syntax (.nft syntax)

## Term Format

- _action::_ The action to take when matched. Refer to Sub-tokens -> Actions for valid options.
- _comment::_ A text comment enclosed in double-quotes. The comment can extend over multiple lines if desired, until a closing quote is encountered.
- _destination-address::_ One or more destination address tokens.
- _destination-port::_ One or more service definition tokens.
- _expiration::_ stop rendering this term after specified date. [YYYY](YYYY.md)-[MM](MM.md)-[DD](DD.md)
- _icmp-type::_ Specify icmp-type code to match.
- _source-address::_ One or more source address tokens.
- _source-port::_ One or more service definition tokens.
- _protocol::_ The network protocol(s) this term will match.
- _logging::_ NFTables system logging (host-based).
- _counter::_ NFTables counter for specific term.

## Sub-tokens

### Actions

- _accept_
- _drop_

### Logging

- _disable_ no packets will be logged on syslog.

All of the below values are accepted, but outcome is exactly the same.

- _true_
- _syslog_
- _local_

### Counter

Any string sub-token in `counter` is accepted. Do note this generator _does not_ implement NFTables `named counters` - this is primarily due to original design decisions to keep each Term into its own chain structure, any support of named counters would simply make the configuration .nft file longer without any additional benefit with the possible exception of the ability to use a single counter-name for multiple terms.

### ICMP Types

This generator normalizes certain capirca policy.py string types to NFTables semantically correct values. The below tables summarize the supported ICMP type codes, the policy.py parent class definition and the NFtables specific value for the same type.

#### IPv4

| ICMPv4 type code | Capirca (policy.py)  | NFtables manual         |
|------------------|----------------------|-------------------------|
| 0                | echo-reply           | echo-reply              |
| 3                | unreachable          | destination-unreachable |
| 4                | source-quench        | source-quench           |
| 5                | redirect             | redirect                |
| 6                | alternate-address    |                         |
| 8                | echo-request         | echo-request            |
| 9                | router-advertisement | router-advertisement    |
| 10               | router-solicitation  | router-solicitation     |
| 11               | time-exceeded        | time-exceeded           |
| 12               | parameter-problem    | parameter-problem       |
| 13               | timestamp-request    | timestamp-request       |
| 14               | timestamp-reply      | timestamp-reply         |
| 15               | information-request  | info-request            |
| 16               | information-reply    | info-reply              |
| 17               | mask-request         | address-mask-request    |
| 18               | mask-reply           | address-mask-reply      |
| 31               | conversion-error     |                         |
| 32               | mobile-redirect      |                         |

#### IPv6

| ICMPv6 type code | Capirca (policy.py)                      | NFtables manual                             |
|------------------|------------------------------------------|---------------------------------------------|
| 1                | destination-unreachable                  | destination-unreachable                     |
| 2                | packet-too-big                           | packet-too-big                              |
| 3                | time-exceeded                            | time-exceeded                               |
| 4                | parameter-problem                        | parameter-problem                           |
| 128              | echo-request                             | echo-request                                |
| 129              | echo-reply                               | echo-reply                                  |
| 130              | multicast-listener-query                 | mld-listener-query                          |
| 131              | multicast-listener-report                | mld-listener-report                         |
| 132              | multicast-listener-done                  | mld-listener-done OR mld-listener-reduction |
| 133              | router-solicit                           | nd-router-solicit                           |
| 134              | router-advertisement                     | nd-router-advert                            |
| 135              | neighbor-solicit                         | nd-neighbor-solicit                         |
| 136              | neighbor-advertisement                   | nd-neighbor-advert                          |
| 137              | redirect-message                         | nd-redirect                                 |
| 138              | router-renumbering                       | router-renumbering                          |
| 139              | icmp-node-information-query              |                                             |
| 140              | icmp-node-information-response           |                                             |
| 141              | inverse-neighbor-discovery-solicitation  | ind-neighbor-solicit                        |
| 142              | inverse-neighbor-discovery-advertisement | ind-neighbor-advert                         |
| 143              | version-2-multicast-listener-report      | mld2-listener-report                        |
| 144              | home-agent-address-discovery-request     |                                             |
| 145              | home-agent-address-discovery-reply       |                                             |
| 146              | mobile-prefix-solicitation               |                                             |
| 147              | mobile-prefix-advertisement              |                                             |
| 148              | certification-path-solicitation          |                                             |
| 149              | certification-path-advertisement         |                                             |
| 151              | multicast-router-advertisement           |                                             |
| 152              | multicast-router-solicitation            |                                             |
| 153              | multicast-router-termination             |                                             |

source: https://www.netfilter.org/projects/nftables/manpage.html

### Option

- _tcp-established_ and _established_ enables conntrack, accept packets that are part of a established connection and related packets. Technically, implements and uses `ESTABLISHED, RELATED` types.

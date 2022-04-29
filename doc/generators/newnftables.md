# nftables

WARNING: A complete rewrite of nftables is in progress.

This file will be updated as functionality extends and may be useful for reference during code reviews.

The NFTables header designation has the following format:
```
target:: newnftables [nf_address_family] [nf_hook] {default_policy_override} {int: base chain priority} {noverbose}
```

Unless otherwise stated, all fields are required unless they're marked optional.

  * nf_address_family: defines the IP address family for the policies. (inet, inet6, mixed)
  * nf_hook: defines the traffic direction and the nftables hook for the rules. (input, output)
  * default_policy_override: **OPTIONAL** defines the default action (ACCEPT, DROP) for non-matching packets. Default behavior is DROP.
  * priority:  **OPTIONAL** By default, this generator creates base chains with a starting priority of 0. Defining an integer value will override this behavior.
  * noverbose: **OPTIONAL** Disable header and term comments in final ACL output. Default behavior is verbose.

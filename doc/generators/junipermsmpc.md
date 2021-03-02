# Juniper MSMPC

The juniper header designation has the following format:

```
target:: juniper [filter name] {inet|inet6|mixed} {noverbose} {ingress|egress}
filter name: defines the name of the juniper msmpc filter.
inet6: specifies the output be for IPv6 only filters.
mixed: specifies the output be for IPv4 and IPv6 filters. This is the default format.
noverbose: omit additional term and address comments.
ingress: filter will be applied in the input direction.
egress: filter will be appliced in the output direction.
```

When inet4 or inet6 is specified, naming tokens with both IPv4 and IPv6 filters will be rendered using only the specified addresses.

When neither ingress or egress is specified, the filter will be applied in both (input-output) directions. This is the default.

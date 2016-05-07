# Introduction

This document covers the YAML format for policy specification, how it
deviates from the Capirca grammar, and the motivation for creating a
different parser at all.

**Note:** Please read the original [Capirca policy format
document](./policy_format.md), as most of the concepts of the grammar
are the same.

# Deviations from Capirca grammar

Sample .yml files are available in this repo, at
`test/yaml_policies/policies`.  Please review them in light of the
following notes.

The ACLs that result from these policies are also available at
`test/yaml_policies/filters_expected`, and are used for automated
regression tests.

## Major differences

* Each .yml file only contains a single policy.  See "Grammar and
  conceptual simplifications" below for reasons.
* There is no `header` section.  Each file contains only one policy, so
  data that belongs in the `header` of a .pol file just lives at the
  top of a .yml file.
* `term` entries are listed in yml-style arrays and given explicit names.

## Minor differences

* `name`: Used as the policy name during output, where possible.
* `address-family`: One of `ipv4` or `ipv6`.  Can be overridden by
  Targets (see "Specifying Targets" below).
* `comment`: YAML-style multi-line strings.
* some entries are specified as comma-delimited strings, and _not_ as
  yml-style arrays.  For example, a `protocol` entry for tcp and udp
  would be specified as `tcp, udp`, not as `[tcp, udp]`.  This may
  turn out to be a poor design choice, and if so will be revised.

## Specifying Targets

Targets are specified as a yml-style array, and are combined with the
`name` and `address-family` elements to produce the final Capirca
Target.

For example, if the `name` was set as `edge-inbound`, and `address-family`
as `ipv4`, the following `target` array entries would result in the
final `target` values as shown:

|`target` array entry|actual `target` value|
|---|---|
|`cisco`|`cisco edge-inbound extended`|
|`juniper`|`juniper edge-inbound inet`|
|`nsxv`|`nsxv inet`|
|`cisco x y z`|`cisco edge-inbound x y z`|
|`juniper x y z`|`juniper edge-inbound x y z`|
|`ciscoasa asa_in`|`ciscoasa asa_in`|
|`gce some data`|`gce some data`|

_Tests for the above are in `test.lib.test_yamlpolicyparser`._

This code currently feels brittle: it was necessary to try to adhere
to the existing Capirca software domain model for backwards
compatibility.  This will likely be revised in some iteration of this
project.

## Comments

`comment` entries are specified as single multi-line strings.  For
example, the following comment in a .yml file:

```
comment: |-
  Denies all traffic to internal IPs except established tcp replies.
  Also denies access to certain public allocations.
```

results in the following output in an ACL:

```
remark Denies all traffic to internal IPs except established tcp replies.
remark Also denies access to certain public allocations.
```

Note that the `|-` marker is significant, as it tells the YAML parser
how to handle newlines.  For more information, see [this StackOverflow
post](http://stackoverflow.com/questions/3790454/in-yaml-how-do-i-break-a-string-over-multiple-lines).

# Motivations for a new parser

The existing PLY parser works correctly in Capirca.  The YAML parser
was added for the following reasons:

* Currently the domain model (that is, the Policy, Header, Term, etc)
  have some methods, but lack others.  In particular, the model relies
  on the data being validated via the parser layer.  Moving validation
  into the model itself strengthens the domain model, which then lends
  itself to better unit and functional testing.
* The fact that data loading is done almost exclusively
  through Capirca .pol file parsing means that it is hard to introduce
  another data source for ACLs, such as a GUI storing information in a
  vendor-neutral database, without going through an intermediary step
  of generating .pol files.
* Introducing another data source as an example mean that other areas
  can tailor the structure to their needs.
* YAML is a standard, simple data format.  This simplification comes
  at the expense of data integrity/safety, but such could be added via
  a library such as [pykwalify](pykwalify.readthedocs.org), or better
  yet, as a stronger domain model.

## Grammar and conceptual simplifications

In addition to the above, there were a few places where the Capirca
grammar felt verbose, or potentially misleading.  It felt reasonable
to add a few ideas and constraints to the .yml file:

* **A single YAML file describes a single ACL.** This feels like a
  reasonable constraint.  The original grammar allows for multiple
  ACLs to be created in a single policy file via multiple separate
  Header sections, which potentially allows for some inconsistency:
  for example, a policy file with multiple headers for different
  targets would generate completely different ACLs depending on which
  target was selected for generation.  This may be a matter of taste,
  but it seems reasonable to have a single-file-to-single-ACL
  constraint.
* **The ACL name and address-family are specified explicitly.** This
  also feels reasonable: a file named 'edge-outbound.yml' would
  conceivably be generating ACLs named 'edge-outbound' for all of its
  targets.  Note that, if needed, the individual targets can override
  the address-family if needed, see "Specifying Targets" above.

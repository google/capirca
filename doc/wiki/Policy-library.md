# policy library

The policy library (see `policy.py`) is intended for parsing the generic
high-level policy files and returning a policy object for acl rendering.
The policy library depends on a [naming library](Naming-library.md) object to
be able to interpret network and service tokens.

## Basic Usage

A policy object is created based on a policy text file.
For information on how to define policy text files, please read the
[Policy Format](PolicyFormat.md) documentation.
For testing, you can use the policies provided in
[policies/pol/](../../../policies/pol/). directory
## Using Policy Objects in Generators
The following section is intended to help developers who would like to create
new output generators, or to modify existing generators.
### Policy Object
A policy object is collection of sections, such as header and terms, as well
as their associated properties.  Each section includes a variety of properties
such as source/destination addresses, protocols, ports, actions, etc.
The `policy.py` module generates policy objects from policy files.
The `ParsePolicy(<policy-string>)` creates a policy object
by passing a string containing a policy to the `ParsePolicy()` class.
### Creating a Policy Object
The steps are:
1. Create a [naming object](Naming-library.md)
1. Read the policy definition data in
1. Generate the policy object
```py
from capirca import naming
from capirca import policy
definitions = naming.Naming('./def/')
policy_text = open('./policies/sample.pol').read()
policy_object = policy.ParsePolicy(policy_text, definitions)
```
The policy object is now available for use.
Typically, this policy object will next be passed to one of the output
generators for rendering an access control filter.
```py
from capirca import juniper
print juniper.Juniper(policy_object)
# Headers
for header, terms in policy.filters:
> header.target
> header.target.filter\_name
# Terms
for header, terms in policy.filters:
    # addresses - lists of nacaddr objects
    terms[x].address[]
    terms[x].destination_address[]
    terms[x].destination_address_exclude[]
    terms[x].source_address[]
    terms[x].source_address_exclude[]
    # ports - list of tuples.  e.g. [(80, 80), (1024, 65535)]
    terms[x].port[]
    terms[x].destination_port[]
    terms[x].source_port[]
    # list of strings
    terms[x].action[]
    terms[x].comment[]
    terms[x].destination_prefix[]
    terms[x].protocol[]
    terms[x].protocol_except[]
    terms[x].option[]
    terms[x].source_prefix[]
    terms[x].traffic_type[]
    terms[x].verbatim[x].value[]
    # string
    terms[x].name
    terms[x].counter
    terms[x].ether_type
    terms[x].logging
    terms[x].loss_priority
    terms[x].packet_length
    terms[x].policer
    terms[x].precedence
    terms[x].qos
    terms[x].routing_instance
    terms[x].source_interface
    # integer
    terms[x].fragment_offset
```

# Introduction
This page is intended to provide the necessary information needed to install the libraries and files needed to begin using capirca.

This page is changing rapidly as the code is migrated from its Google roots and to open source, and while the new structure of the code and usage is finalized. Unfortunately, this page may be frequently out of date for short periods, but we will strive to keep it current.

In its current form, this page is intended to provide a quick-start guide. See the other wiki pages for more details.

# Details
Quick Start
In the install directory, simply run:

```
python aclgen.py
```

This should generate sample output filters for cisco, juniper and iptables from the provided `sample.pol` policy file and the predefined network and service definitions.

Optionally, you can provide arguments to the `aclgen.py` script the specifies a non-default location for naming definition, policy files and filter output directory.

```
python aclgen.py --help
```

# Manually Generating Naming, Policy, and Platform Generator Output
The following commands can be run from the parent installation directory to manually create a naming definitions object, policy objection, and render generator filter output.

Import naming library and create naming object from definitions files:

```
from lib import naming
defs = naming.Naming(‘./def’)
```

Import policy library, read in the policy data, and create a policy object:

```
from lib import policy
conf = open(‘./policies/sample.pol’).read()
pol = policy.ParsePolicy(conf, defs, optimize=True)
```

Import a generator library (juniper in this case) and output a policy in the desired format:

```
from lib import juniper
for header in pol.headers:
  if ‘juniper’ in header.platforms:
    jcl = True …
if jcl:
  output = juniper.Juniper(pol)
  print output
```

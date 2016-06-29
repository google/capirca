These folders contain YAML-format policies for Capirca.  YAML is an
easier format to deal with than a custom parser, and also provides a
POC/dev basis for future grammars with location/client-specific
requirements.

The "defs" files are currently still in the proprietary Capirca
format, YAML equivalents will be added.

Folders:

* `filters_expected`: filters that are expected to be generated given
  the `def` and `policies` folders.
* `filters_actual`: the filters actually generated, which are compared
  with the `filters_expected` folder.  This folder is not committed to
  version control.  It is deleted on every test run.  The files are
  generated to this folder, rather than a temporary folder, to let you
  inspect the output between runs and correct any errors.

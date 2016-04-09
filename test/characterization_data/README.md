These folders contain data for characterization tests; i.e., tests
that describe the actual behaviour of the current code.

Folders:

* `filters_expected`: filters that are expected to be generated given
  the `def` and `policies` folders.
* `filters_actual`: the filters actually generated, which are compared
  with the `filters_expected` folder.  This folder is not committed to
  version control.  It is deleted on every test run.  The files are
  generated to this folder, rather than a temporary folder, to let you
  inspect the output between runs and correct any errors.

The tests in the folder ../../tests folder don't follow the required
naming convention for unittest discovery.  For tests to be
automatically discovered using 'python -m unittest discover', the test
modules must be named 'test_xxx.py'.

This directory is a temporary hack of symlinks from the ../../tests
folder to here, where the symlinks have the proper names.  This allows
full test discovery of all tests until we come up with a simple
strategy for actually running the tests.
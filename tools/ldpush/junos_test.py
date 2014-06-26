#!/usr/bin/python

"""Tests for junos devices."""

import tempfile
import textwrap
import mox

import unittest
import junos
import paramiko_device
import push_exceptions as exceptions


class JunosTest(unittest.TestCase):

  def setUp(self):
    self._mox = mox.Mox()
    self.device = junos.JunosDevice(host='pr01.dub01')

  def tearDown(self):
    self._mox.UnsetStubs()
    self._mox.ResetAll()
    self._mox.UnsetStubs()

  def testGetConfigSuccessfulConfigTransfer(self):
    self._mox.StubOutWithMock(paramiko_device.ParamikoDevice, '_Cmd')
    paramiko_device.ParamikoDevice._Cmd(
        'show configuration', mode=None, merge_stderr_first=False,
        require_low_chanid=True).AndReturn(
            'Some configuration\n response.')
    self._mox.ReplayAll()
    response = self.device._GetConfig('running-config')
    self._mox.VerifyAll()
    self.assertEquals('Some configuration\n response.', response)

  def testGetConfigFailedConfigTransfer(self):
    self._mox.StubOutWithMock(paramiko_device.ParamikoDevice, '_Cmd')
    paramiko_device.ParamikoDevice._Cmd(
        'show configuration', mode=None, merge_stderr_first=False,
        require_low_chanid=True).AndRaise(exceptions.CmdError)
    self._mox.ReplayAll()
    self.assertRaises(exceptions.GetConfigError, self.device._GetConfig,
                      'running-config')
    self._mox.VerifyAll()

  def testGetConfigEmptyConfigTransfer(self):
    self._mox.StubOutWithMock(paramiko_device.ParamikoDevice, '_Cmd')
    paramiko_device.ParamikoDevice._Cmd(
        'show configuration', mode=None, merge_stderr_first=False,
        require_low_chanid=True).AndReturn('')
    self._mox.ReplayAll()
    self.assertRaises(exceptions.EmptyConfigError, self.device._GetConfig,
                      'running-config')
    self._mox.VerifyAll()

  def testGetConfigSuccessfulFileTransfer(self):
    tempfile_ptr = tempfile.NamedTemporaryFile()
    tempfile_ptr.write('Fake file content.')
    tempfile_ptr.seek(0)
    self._mox.StubOutWithMock(tempfile, 'NamedTemporaryFile')
    self._mox.StubOutWithMock(junos.JunosDevice, '_GetFileViaSftp')

    tempfile.NamedTemporaryFile().AndReturn(tempfile_ptr)
    self.device._GetFileViaSftp(local_filename=tempfile_ptr.name,
                                remote_filename='/var/tmp/testfile')
    self._mox.ReplayAll()
    response = self.device._GetConfig('/var/tmp/testfile')
    self._mox.VerifyAll()
    self.assertEquals('Fake file content.', response)

  def testGetConfigFailedFileTransfer(self):
    tempfile_ptr = tempfile.NamedTemporaryFile()
    self._mox.StubOutWithMock(tempfile, 'NamedTemporaryFile')
    self._mox.StubOutWithMock(junos.JunosDevice, '_GetFileViaSftp')

    tempfile.NamedTemporaryFile().AndReturn(tempfile_ptr)
    self.device._GetFileViaSftp(
        local_filename=tempfile_ptr.name,
        remote_filename='/var/tmp/testfile').AndRaise(IOError)
    self._mox.ReplayAll()
    self.assertRaises(exceptions.GetConfigError, self.device._GetConfig,
                      '/var/tmp/testfile')
    self._mox.VerifyAll()

  def testCleanupErrorLine(self):
    self.assertEquals('', self.device._CleanupErrorLine(''))
    self.assertEquals('a', self.device._CleanupErrorLine('a'))
    self.assertEquals('invalid value ',
                      self.device._CleanupErrorLine(
                          'invalid value \'257\' in ip address: \'257.0.0.0'))
    self.assertEquals('description ',
                      self.device._CleanupErrorLine('description "foo";'))
    self.assertEquals(
        '', self.device._CleanupErrorLine('+   description "error: foo";'))
    self.assertEquals(
        '', self.device._CleanupErrorLine('-   description "1 errors";'))
    self.assertEquals(
        '', self.device._CleanupErrorLine('!   description "error foo";'))
    self.assertEquals('foo -1', self.device._CleanupErrorLine('foo -1'))

  def testLoadErrors(self):
    # Make an alias for the function under test, _RaiseExceptionIfLoadError,
    # because writing "self.device._RaiseExceptionIfLoadError" is verbose.
    test_function = self.device._RaiseExceptionIfLoadError

    # Check some non-throwing cases.
    self.assertTrue(test_function('') is None)
    self.assertTrue(test_function('', expect_config_check=True) is None)
    self.assertTrue(
        test_function('+ description "error: syntax error";',
                      expect_config_check=True)
        is None)
    self.assertTrue(
        test_function('! description "error: syntax error";',
                      expect_config_check=True)
        is None)
    self.assertTrue(test_function('[edit ... ]') is None)
    self.assertTrue(test_function('[edit ... ]\n error: foo') is None)
    self.assertTrue(test_function('[edit ... ]\n+ error: foo') is None)
    missing_re_output = textwrap.dedent("""\
        Entering configuration mode
        load complete

        error: Could not connect to re1 : No route to host
        warning: Cannot connect to other RE, ignoring it
        commit complete
        Exiting configuration mode
        """)
    self.assertTrue(test_function(missing_re_output, expect_commit=True)
                    is None)

    # This is a successful commit.
    warning_output = textwrap.dedent("""\
      [edit]
      Entering configuration mode
         'interfaces'
           warning: statement has no contents; ignored

      load complete
      commit complete
      Exiting configuration mode
      """)
    self.assertIsNone(
        test_function(warning_output, expect_config_check=False,
                      expect_commit=True))
    # Also a successful commit from a switch-type device - b/10202762.
    output = textwrap.dedent("""\
        Entering configuration mode
        |load complete
        configuration check succeedscommit complete
        Exiting configuration mode
        """)
    self.assertIsNone(
        test_function(output, expect_config_check=True, expect_commit=True))

    # Check throwing cases.
    self.assertRaises(
        exceptions.SetConfigSyntaxError,
        test_function, 'foo\n  syntax error: ')
    self.assertRaises(
        exceptions.SetConfigError,
        test_function, '  load failed (1 errors)')
    self.assertRaises(
        exceptions.SetConfigError,
        test_function, '  load complete (1 errors)')
    self.assertRaises(
        exceptions.SetConfigError,
        test_function, '[edit ...]\n syntax error\nerror: foo')
    self.assertRaises(
        exceptions.SetConfigError,
        test_function, 'error: configuration check-out failed')
    self.assertRaises(
        exceptions.SetConfigSyntaxError,
        test_function, 'syntax error: "connect to re1 :"')
    self.assertRaises(
        exceptions.SetConfigSyntaxError,
        test_function, 'syntax error: connect to re1 :')
    # Check all JUNOS_LOAD_ERRORS strings
    for error in self.device.JUNOS_LOAD_ERRORS:
      self.assertRaises(exceptions.SetConfigError,
                        test_function, error)
      self.assertRaises(exceptions.SetConfigError,
                        test_function, error, expect_commit=True)
    # Check the commit_check parameter.
    self.assertRaises(
        exceptions.SetConfigSyntaxError,
        test_function, '  load failed (1 errors)', expect_config_check=True)
    self.assertRaises(
        exceptions.SetConfigSyntaxError,
        test_function, 'error:\nsyntax error', expect_config_check=True)
    self.assertRaises(
        exceptions.SetConfigError,
        test_function, 'configuration check succeeds\n(1 errors)',
        expect_config_check=True)
    self.assertRaises(
        exceptions.SetConfigSyntaxError,
        test_function, '\'configuration check succeeds\'\nerror:',
        expect_config_check=True)
    # Check that we don't raise a syntax error just because someone wrote
    # "syntax error" in a description.
    self.assertRaises(
        exceptions.SetConfigError,
        test_function, '+description "syntax error";\nerror:')
    # This is nearly-real output from b/7176238, including a message about a
    # missing RE.
    syntax_error_with_missing_re = textwrap.dedent("""
        Entering configuration mode
        Users currently editing the configuration:
          netops terminal p3 (pid 44448) on since 2012-09-05 10:00:49 PDT, ...
              [edit]
          netops terminal p4 (pid 63408) on since 2012-09-16 23:57:00 PDT, ...
              private [edit]
        |\x08tmpPjACa3:1:(10) syntax error: deactivate
        load complete (1 errors)

        error: Could not connect to re1 : No route to host
        warning: Cannot connect to other RE, ignoring it
        commit complete
        Exiting configuration mode
        """)
    self.assertRaises(exceptions.SetConfigSyntaxError,
                      test_function, syntax_error_with_missing_re,
                      expect_config_check=False,
                      expect_commit=False)
    # Also do the test with commit_check=True
    self.assertRaises(exceptions.SetConfigSyntaxError,
                      test_function, syntax_error_with_missing_re,
                      expect_config_check=False, expect_commit=True)
    failed_commit_b_9750034 = textwrap.dedent("""\
      re0:
      error: Could not connect to re1 : No route to host

      [edit]
      """)
    self.assertRaises(
        exceptions.SetConfigError,
        test_function, failed_commit_b_9750034, expect_config_check=False,
        expect_commit=True)


if __name__ == '__main__':
  unittest.main()

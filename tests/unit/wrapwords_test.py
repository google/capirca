import pytest
from capirca.lib.aclgenerator import WrapWords

SINGLE_LINE_OVERFLOW_TEXT_LONG = \
    "http://github.com/google/capirca/commit/c5" + \
    "6ddf19e2679892ff078cf27aeb18310c2697ed This " + \
    "is a long header. It's long on purpose. It's " + \
    "purpose is to test that the splitting works co" + \
    "rrectly. It should be well over the line limit" + \
    ". If it is shorter, it would not test the limit."

SINGLE_LINE_OVERFLOW_TEXT_LONG_EXPECTED = [
    'http://github.com/google/capirca/commit/c56ddf19e2679892ff078cf27aeb18', 
    '310c2697ed', 
    "This is a long header. It's long on purpose. It's purpose is to test", 
    'that the splitting works correctly. It should be well over the line', 
    'limit. If it is shorter, it would not test the limit.'
]

MULTI_LINE_OVERFLOW_TEXT_LONG = \
    "this is a veryveryveryveryveryveryveryveryver" + \
    "yveryveryveryveryveryveryveryveryveryveryvery" + \
    "veryveryveryveryveryveryveryveryveryveryveryv" + \
    "eryveryveryveryveryveryveryveryveryveryvery long word"

MULTI_LINE_OVERFLOW_TEXT_LONG_EXPECTED = [
    'this is a', 
    'veryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryve', 
    'ryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryvery', 
    'veryveryveryveryveryveryvery', 
    'long word'
]

NO_OVERFLOW_LONG = \
    "This " + \
    "is a long header. It's long on purpose. It's " + \
    "purpose is to test that the splitting works co" + \
    "rrectly. It should be well over the line limit" + \
    ". If it is shorter, it would not test the limit."

NO_OVERFLOW_LONG_EXPECTED = [
    "This is a long header. It's long on purpose. It's purpose is to test", 
    'that the splitting works correctly. It should be well over the line', 
    'limit. If it is shorter, it would not test the limit.'
]

NO_OVERFLOW_SHORT = \
    "This is a short line of text"

NO_OVERFLOW_SHORT_EXPECTED = [
    "This is a short line of text"
]

@pytest.mark.parametrize("test_input,expected", [
    (NO_OVERFLOW_SHORT, NO_OVERFLOW_SHORT_EXPECTED),
    (NO_OVERFLOW_LONG, NO_OVERFLOW_LONG_EXPECTED),
    (SINGLE_LINE_OVERFLOW_TEXT_LONG, SINGLE_LINE_OVERFLOW_TEXT_LONG_EXPECTED),
    (MULTI_LINE_OVERFLOW_TEXT_LONG, MULTI_LINE_OVERFLOW_TEXT_LONG_EXPECTED)
    ]
)
def testWrapWords(test_input, expected):
    result = WrapWords([test_input], 70)

    assert all((res == exp for res, exp in zip(result, expected)))

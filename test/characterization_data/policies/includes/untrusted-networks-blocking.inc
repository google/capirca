term deny-from-bogons {
  comment:: "this is a sample edge input filter with a very very very long and
        multi-line comment that"
  comment:: "also has multiple entries."
  source-address:: BOGON
  action:: deny
}

term deny-from-reserved {
  source-address:: RESERVED
  action:: deny
}

term deny-to-rfc1918 {
  destination-address:: RFC1918
  action:: deny
}


"""Tests for google3.third_party.py.capirca.lib.gcp_hf.py."""

import json
from unittest import mock
from absl.testing import absltest

from absl.testing import parameterized
from capirca.lib import gcp
from capirca.lib import gcp_hf
from capirca.lib import nacaddr
from capirca.lib import naming
from capirca.lib import policy

HEADER_NO_OPTIONS = """
header {
  comment:: "The general policy comment."
  target:: gcp_hf displayname
}
"""

HEADER_OPTION_MAX = """
header {
  comment:: "The general policy comment."
  target:: gcp_hf displayname 20
}
"""

HEADER_OPTION_EGRESS = """
header {
  comment:: "The general policy comment."
  target:: gcp_hf displayname EGRESS
}
"""

HEADER_OPTION_EGRESS_2 = """
header {
  comment:: "The general policy comment."
  target:: gcp_hf displayname2 EGRESS
}
"""

HEADER_OPTION_AF = """
header {
  comment:: "The general policy comment."
  target:: gcp_hf displayname inet
}
"""

HEADER_OPTION_HIGH_QUOTA = """
header {
  comment:: "The general policy comment."
  target:: gcp_hf displayname 500
}
"""

HEADER_OPTION_EGRESS_HIGH_QUOTA = """
header {
  comment:: "The general policy comment."
  target:: gcp_hf displayname EGRESS 500
}
"""

HEADER_OPTION_EGRESS_AND_MAX = """
header {
  comment:: "The general policy comment."
  target:: gcp_hf displayname EGRESS 20
}
"""

HEADER_OPTION_EGRESS_AND_AF = """
header {
  comment:: "The general policy comment."
  target:: gcp_hf displayname EGRESS inet
}
"""

HEADER_OPTION_EGRESS_INET6 = """
header {
  comment:: "The general policy comment."
  target:: gcp_hf displayname EGRESS inet6 ga
}
"""

HEADER_OPTION_MAX_AND_AF = """
header {
  comment:: "The general policy comment."
  target:: gcp_hf displayname 20 inet
}
"""

HEADER_VERY_LOW_DEFAULT_MAX = """
header {
  comment:: "The general policy comment."
  target:: gcp_hf displayname 1
}
"""

HEADER_OPTION_BETA = """
header {
  comment:: "The general policy comment."
  target:: gcp_hf displayname inet beta
}
"""

HEADER_OPTION_GA = """
header {
  comment:: "The general policy comment."
  target:: gcp_hf displayname ga
}
"""

HEADER_GA_NO_INET_OPTIONS = """
header {
  comment:: "The general policy comment."
  target:: gcp_hf displayname ga
}
"""

HEADER_OPTION_INET6 = """
header {
  comment:: "The general policy comment."
  target:: gcp_hf displayname inet6 ga
}
"""

HEADER_OPTION_MIXED = """
header {
  comment:: "The general policy comment."
  target:: gcp_hf displayname mixed ga
}
"""

HEADER_OPTION_EGRESS_MIXED = """
header {
  comment:: "The general policy comment."
  target:: gcp_hf displayname EGRESS mixed ga
}
"""

BAD_HEADER_NO_DISPLAYNAME = """
header {
  comment:: "Header without a policy name."
  target:: gcp_hf
}
"""

BAD_HEADER_LONG_DISPLAYNAME = """
header {
  comment:: "Using a display name with 64 characters."
  target:: gcp_hf this-is-a-very-very-long-policy-name-which-is-over-63-characters
}
"""

BAD_HEADER_INVALID_DISPLAYNAME_1 = """
header {
  comment:: "Using a display name with an upper case letter."
  target:: gcp_hf Displayname
}
"""

BAD_HEADER_INVALID_DISPLAYNAME_2 = """
header {
  comment:: "Using a display name with an underscore character."
  target:: gcp_hf display_name
}
"""

BAD_HEADER_INVALID_DISPLAYNAME_3 = """
header {
  comment:: "Using a display name that ends in a dash."
  target:: gcp_hf displayname-
}
"""

BAD_HEADER_UNKNOWN_OPTION = """
header {
  comment:: "The general policy comment."
  target:: gcp_hf displayname INGRESS randomOption
}
"""

BAD_HEADER_UNKNOWN_DIRECTION = """
header {
  comment:: "The general policy comment."
  target:: gcp_hf displayname BIGRESS
}
"""

BAD_HEADER_INVALID_MAX_COST = """
header {
  comment:: "The general policy comment."
  target:: gcp_hf displayname INGRESS 888888888
}
"""

BAD_HEADER_WRONG_PLATFORM = """
header {
  comment:: "The general policy comment."
  target:: wrong_platform
}
"""

TERM_ALLOW_ALL_INTERNAL = """
term allow-internal-traffic {
  comment:: "Generic description"
  protocol:: tcp icmp udp
  action:: next
}
"""

TERM_PLATFORM_ALLOW_ALL_INTERNAL = """
term allow-internal-traffic {
  comment:: "Generic description"
  protocol:: tcp icmp udp
  action:: next
  platform:: gcp_hf
}
"""

TERM_PLATFORM_EXCLUDE = """
term allow-internal-traffic {
  comment:: "Generic description"
  protocol:: tcp icmp udp
  action:: next
  platform-exclude:: gcp_hf
}
"""

TERM_ALLOW_MULTIPLE_PROTOCOL = """
term allow-internal-traffic {
  comment:: "Generic description"
  source-address:: PUBLIC_NAT
  protocol:: tcp icmp udp
  action:: next
}
"""

TERM_ALLOW_MULTIPLE_PROTOCOL_ICMPV6 = """
term allow-internal-traffic {
  comment:: "Generic description"
  source-address:: PUBLIC_NAT
  protocol:: tcp icmpv6 udp
  action:: next
}
"""

TERM_ALLOW_DNS = """
term allow-dns-traffic {
  comment:: "Generic description"
  source-address:: PUBLIC_NAT
  protocol:: tcp udp
  destination-port:: DNS
  action:: next
}
"""

TERM_ALLOW_PORT = """
term allow-traffic-to-port {
  comment:: "Generic description"
  source-address:: PUBLIC_NAT
  protocol:: tcp
  destination-port:: PORT
  action:: next
}
"""

TERM_ALLOW_EGRESS_PORT = """
term allow-traffic-to-port {
  comment:: "Generic description"
  destination-address:: PUBLIC_NAT
  protocol:: tcp
  destination-port:: PORT
  action:: next
}
"""

TERM_ALLOW_PORT_RANGE = """
term allow-port-range {
  comment:: "Generic description"
  source-address:: PUBLIC_NAT
  protocol:: tcp
  destination-port:: RANGE
  action:: next
}
"""

TERM_RESTRICT_EGRESS = """
term restrict_egress {
  comment:: "Generic description"
  destination-address:: PUBLIC_NAT
  protocol:: tcp icmp udp
  action:: next
}
"""

TERM_DENY_INGRESS = """
term default-deny-ingress {
  comment:: "Generic description"
  action:: deny
}
"""

TERM_DENY_EGRESS = """
term default-deny-egress {
  comment:: "Generic description"
  action:: deny
}
"""

TERM_WITH_TARGET_RESOURCES = """
term default-deny-ingress-on-target {
  comment:: "Generic description"
  source-address:: ANY
  action:: deny
  target-resources:: (project1, vpc1)
  target-resources:: (project2, vpc2)
}
"""

TERM_WITH_TARGET_RESOURCES_2 = """
term default-deny-ingress-on-target {
  comment:: "Generic description"
  source-address:: ANY
  action:: deny
  target-resources:: [(project1, vpc1),(project2,vpc2)]
}
"""

TERM_WITH_LOGGING = """
term term-with-logging {
  comment:: "Generic description"
  source-address:: ANY
  protocol:: tcp
  action:: accept
  logging:: true
}
"""

TERM_NO_COMMENT = """
term allow-internal-traffic {
  source-address:: INTERNAL
  protocol:: tcp icmp udp
  action:: next
}
"""

TERM_LONG_COMMENT = """
term allow-internal-traffic {
  comment:: "This is a very long description, it is longer than sixty-four chars"
  source-address:: INTERNAL
  protocol:: tcp icmp udp
  action:: next
}
"""

TERM_NUMBERED_PROTOCOL = """
  term term-numbered-protocol {
  comment:: "Generic description"
  source-address:: PUBLIC_NAT
  protocol:: igmp
  action:: next
}
"""

BAD_TERM_USING_SOURCE_TAG = """
  term bad-term-with-tag {
  comment:: "Generic description"
  source-address:: PUBLIC_NAT
  source-tag:: a-tag
  protocol:: tcp icmp udp
  action:: next
}
"""

BAD_TERM_USING_DEST_TAG = """
  term bad-term-with-tag {
  comment:: "Generic description"
  source-address:: PUBLIC_NAT
  destination-tag:: a-tag
  protocol:: tcp icmp udp
  action:: next
}
"""

BAD_TERM_SOURCE_PORT = """
term allow-traffic-from-port {
  comment:: "Generic description"
  destination-address:: INTERNAL
  protocol:: tcp
  source-port:: PORT
  action:: next
}
"""

BAD_TERM_TARGET_RESOURCES = """
term hf-too-many-target-resources {
  comment:: "Generic description"
  destination-address:: INTERNAL
  protocol:: tcp
  target-resources:: (proj1,vpc1)
  target-resources:: (proj2,vpc2)
  target-resources:: (proj3,vpc3)
  target-resources:: (proj4,vpc4)
  target-resources:: (proj5,vpc5)
  target-resources:: (proj6,vpc6)
  target-resources:: (proj7,vpc7)
  target-resources:: (proj8,vpc8)
  target-resources:: (proj9,vpc9)
  target-resources:: (proj10,vpc10)
  target-resources:: (proj11,vpc11)
  target-resources:: (proj12,vpc12)
  target-resources:: (proj13,vpc13)
  target-resources:: (proj14,vpc14)
  target-resources:: (proj15,vpc15)
  target-resources:: (proj16,vpc16)
  target-resources:: (proj17,vpc17)
  target-resources:: (proj18,vpc18)
  target-resources:: (proj19,vpc19)
  target-resources:: (proj20,vpc20)
  target-resources:: (proj21,vpc21)
  target-resources:: (proj22,vpc22)
  target-resources:: (proj23,vpc23)
  target-resources:: (proj24,vpc24)
  target-resources:: (proj25,vpc25)
  target-resources:: (proj26,vpc26)
  target-resources:: (proj27,vpc27)
  target-resources:: (proj28,vpc28)
  target-resources:: (proj29,vpc29)
  target-resources:: (proj30,vpc30)
  target-resources:: (proj31,vpc31)
  target-resources:: (proj32,vpc32)
  target-resources:: (proj33,vpc33)
  target-resources:: (proj34,vpc34)
  target-resources:: (proj35,vpc35)
  target-resources:: (proj36,vpc36)
  target-resources:: (proj37,vpc37)
  target-resources:: (proj38,vpc38)
  target-resources:: (proj39,vpc39)
  target-resources:: (proj40,vpc40)
  target-resources:: (proj41,vpc41)
  target-resources:: (proj42,vpc42)
  target-resources:: (proj43,vpc43)
  target-resources:: (proj44,vpc44)
  target-resources:: (proj45,vpc45)
  target-resources:: (proj46,vpc46)
  target-resources:: (proj47,vpc47)
  target-resources:: (proj48,vpc48)
  target-resources:: (proj49,vpc49)
  target-resources:: (proj50,vpc50)
  target-resources:: (proj51,vpc51)
  target-resources:: (proj52,vpc52)
  target-resources:: (proj53,vpc53)
  target-resources:: (proj54,vpc54)
  target-resources:: (proj55,vpc55)
  target-resources:: (proj56,vpc56)
  target-resources:: (proj57,vpc57)
  target-resources:: (proj58,vpc58)
  target-resources:: (proj59,vpc59)
  target-resources:: (proj60,vpc60)
  target-resources:: (proj61,vpc61)
  target-resources:: (proj62,vpc62)
  target-resources:: (proj63,vpc63)
  target-resources:: (proj64,vpc64)
  target-resources:: (proj65,vpc65)
  target-resources:: (proj66,vpc66)
  target-resources:: (proj67,vpc67)
  target-resources:: (proj68,vpc68)
  target-resources:: (proj69,vpc69)
  target-resources:: (proj70,vpc70)
  target-resources:: (proj71,vpc71)
  target-resources:: (proj72,vpc72)
  target-resources:: (proj73,vpc73)
  target-resources:: (proj74,vpc74)
  target-resources:: (proj75,vpc75)
  target-resources:: (proj76,vpc76)
  target-resources:: (proj77,vpc77)
  target-resources:: (proj78,vpc78)
  target-resources:: (proj79,vpc79)
  target-resources:: (proj80,vpc80)
  target-resources:: (proj81,vpc81)
  target-resources:: (proj82,vpc82)
  target-resources:: (proj83,vpc83)
  target-resources:: (proj84,vpc84)
  target-resources:: (proj85,vpc85)
  target-resources:: (proj86,vpc86)
  target-resources:: (proj87,vpc87)
  target-resources:: (proj88,vpc88)
  target-resources:: (proj89,vpc89)
  target-resources:: (proj90,vpc90)
  target-resources:: (proj91,vpc91)
  target-resources:: (proj92,vpc92)
  target-resources:: (proj93,vpc93)
  target-resources:: (proj94,vpc94)
  target-resources:: (proj95,vpc95)
  target-resources:: (proj96,vpc96)
  target-resources:: (proj97,vpc97)
  target-resources:: (proj98,vpc98)
  target-resources:: (proj99,vpc99)
  target-resources:: (proj100,vpc100)
  target-resources:: (proj101,vpc101)
  target-resources:: (proj102,vpc102)
  target-resources:: (proj103,vpc103)
  target-resources:: (proj104,vpc104)
  target-resources:: (proj105,vpc105)
  target-resources:: (proj106,vpc106)
  target-resources:: (proj107,vpc107)
  target-resources:: (proj108,vpc108)
  target-resources:: (proj109,vpc109)
  target-resources:: (proj110,vpc110)
  target-resources:: (proj111,vpc111)
  target-resources:: (proj112,vpc112)
  target-resources:: (proj113,vpc113)
  target-resources:: (proj114,vpc114)
  target-resources:: (proj115,vpc115)
  target-resources:: (proj116,vpc116)
  target-resources:: (proj117,vpc117)
  target-resources:: (proj118,vpc118)
  target-resources:: (proj119,vpc119)
  target-resources:: (proj120,vpc120)
  target-resources:: (proj121,vpc121)
  target-resources:: (proj122,vpc122)
  target-resources:: (proj123,vpc123)
  target-resources:: (proj124,vpc124)
  target-resources:: (proj125,vpc125)
  target-resources:: (proj126,vpc126)
  target-resources:: (proj127,vpc127)
  target-resources:: (proj128,vpc128)
  target-resources:: (proj129,vpc129)
  target-resources:: (proj130,vpc130)
  target-resources:: (proj131,vpc131)
  target-resources:: (proj132,vpc132)
  target-resources:: (proj133,vpc133)
  target-resources:: (proj134,vpc134)
  target-resources:: (proj135,vpc135)
  target-resources:: (proj136,vpc136)
  target-resources:: (proj137,vpc137)
  target-resources:: (proj138,vpc138)
  target-resources:: (proj139,vpc139)
  target-resources:: (proj140,vpc140)
  target-resources:: (proj141,vpc141)
  target-resources:: (proj142,vpc142)
  target-resources:: (proj143,vpc143)
  target-resources:: (proj144,vpc144)
  target-resources:: (proj145,vpc145)
  target-resources:: (proj146,vpc146)
  target-resources:: (proj147,vpc147)
  target-resources:: (proj148,vpc148)
  target-resources:: (proj149,vpc149)
  target-resources:: (proj150,vpc150)
  target-resources:: (proj151,vpc151)
  target-resources:: (proj152,vpc152)
  target-resources:: (proj153,vpc153)
  target-resources:: (proj154,vpc154)
  target-resources:: (proj155,vpc155)
  target-resources:: (proj156,vpc156)
  target-resources:: (proj157,vpc157)
  target-resources:: (proj158,vpc158)
  target-resources:: (proj159,vpc159)
  target-resources:: (proj160,vpc160)
  target-resources:: (proj161,vpc161)
  target-resources:: (proj162,vpc162)
  target-resources:: (proj163,vpc163)
  target-resources:: (proj164,vpc164)
  target-resources:: (proj165,vpc165)
  target-resources:: (proj166,vpc166)
  target-resources:: (proj167,vpc167)
  target-resources:: (proj168,vpc168)
  target-resources:: (proj169,vpc169)
  target-resources:: (proj170,vpc170)
  target-resources:: (proj171,vpc171)
  target-resources:: (proj172,vpc172)
  target-resources:: (proj173,vpc173)
  target-resources:: (proj174,vpc174)
  target-resources:: (proj175,vpc175)
  target-resources:: (proj176,vpc176)
  target-resources:: (proj177,vpc177)
  target-resources:: (proj178,vpc178)
  target-resources:: (proj179,vpc179)
  target-resources:: (proj180,vpc180)
  target-resources:: (proj181,vpc181)
  target-resources:: (proj182,vpc182)
  target-resources:: (proj183,vpc183)
  target-resources:: (proj184,vpc184)
  target-resources:: (proj185,vpc185)
  target-resources:: (proj186,vpc186)
  target-resources:: (proj187,vpc187)
  target-resources:: (proj188,vpc188)
  target-resources:: (proj189,vpc189)
  target-resources:: (proj190,vpc190)
  target-resources:: (proj191,vpc191)
  target-resources:: (proj192,vpc192)
  target-resources:: (proj193,vpc193)
  target-resources:: (proj194,vpc194)
  target-resources:: (proj195,vpc195)
  target-resources:: (proj196,vpc196)
  target-resources:: (proj197,vpc197)
  target-resources:: (proj198,vpc198)
  target-resources:: (proj199,vpc199)
  target-resources:: (proj200,vpc200)
  target-resources:: (proj201,vpc201)
  target-resources:: (proj202,vpc202)
  target-resources:: (proj203,vpc203)
  target-resources:: (proj204,vpc204)
  target-resources:: (proj205,vpc205)
  target-resources:: (proj206,vpc206)
  target-resources:: (proj207,vpc207)
  target-resources:: (proj208,vpc208)
  target-resources:: (proj209,vpc209)
  target-resources:: (proj210,vpc210)
  target-resources:: (proj211,vpc211)
  target-resources:: (proj212,vpc212)
  target-resources:: (proj213,vpc213)
  target-resources:: (proj214,vpc214)
  target-resources:: (proj215,vpc215)
  target-resources:: (proj216,vpc216)
  target-resources:: (proj217,vpc217)
  target-resources:: (proj218,vpc218)
  target-resources:: (proj219,vpc219)
  target-resources:: (proj220,vpc220)
  target-resources:: (proj221,vpc221)
  target-resources:: (proj222,vpc222)
  target-resources:: (proj223,vpc223)
  target-resources:: (proj224,vpc224)
  target-resources:: (proj225,vpc225)
  target-resources:: (proj226,vpc226)
  target-resources:: (proj227,vpc227)
  target-resources:: (proj228,vpc228)
  target-resources:: (proj229,vpc229)
  target-resources:: (proj230,vpc230)
  target-resources:: (proj231,vpc231)
  target-resources:: (proj232,vpc232)
  target-resources:: (proj233,vpc233)
  target-resources:: (proj234,vpc234)
  target-resources:: (proj235,vpc235)
  target-resources:: (proj236,vpc236)
  target-resources:: (proj237,vpc237)
  target-resources:: (proj238,vpc238)
  target-resources:: (proj239,vpc239)
  target-resources:: (proj240,vpc240)
  target-resources:: (proj241,vpc241)
  target-resources:: (proj242,vpc242)
  target-resources:: (proj243,vpc243)
  target-resources:: (proj244,vpc244)
  target-resources:: (proj245,vpc245)
  target-resources:: (proj246,vpc246)
  target-resources:: (proj247,vpc247)
  target-resources:: (proj248,vpc248)
  target-resources:: (proj249,vpc249)
  target-resources:: (proj250,vpc250)
  target-resources:: (proj251,vpc251)
  target-resources:: (proj252,vpc252)
  target-resources:: (proj253,vpc253)
  target-resources:: (proj254,vpc254)
  target-resources:: (proj255,vpc255)
  target-resources:: (proj256,vpc256)
  target-resources:: (proj257,vpc257)
  action:: next
}
"""

BAD_TERM_DESTINATION_PORTS = """
term hf-too-many-destination-ports {
  comment:: "Generic description"
  source-address:: INTERNAL
  destination-port:: TP2000
  destination-port:: TP2001
  destination-port:: TP2002
  destination-port:: TP2003
  destination-port:: TP2004
  destination-port:: TP2005
  destination-port:: TP2006
  destination-port:: TP2007
  destination-port:: TP2008
  destination-port:: TP2009
  destination-port:: TP2010
  destination-port:: TP2011
  destination-port:: TP2012
  destination-port:: TP2013
  destination-port:: TP2014
  destination-port:: TP2015
  destination-port:: TP2016
  destination-port:: TP2017
  destination-port:: TP2018
  destination-port:: TP2019
  destination-port:: TP2020
  destination-port:: TP2021
  destination-port:: TP2022
  destination-port:: TP2023
  destination-port:: TP2024
  destination-port:: TP2025
  destination-port:: TP2026
  destination-port:: TP2027
  destination-port:: TP2028
  destination-port:: TP2029
  destination-port:: TP2030
  destination-port:: TP2031
  destination-port:: TP2032
  destination-port:: TP2033
  destination-port:: TP2034
  destination-port:: TP2035
  destination-port:: TP2036
  destination-port:: TP2037
  destination-port:: TP2038
  destination-port:: TP2039
  destination-port:: TP2040
  destination-port:: TP2041
  destination-port:: TP2042
  destination-port:: TP2043
  destination-port:: TP2044
  destination-port:: TP2045
  destination-port:: TP2046
  destination-port:: TP2047
  destination-port:: TP2048
  destination-port:: TP2049
  destination-port:: TP2050
  destination-port:: TP2051
  destination-port:: TP2052
  destination-port:: TP2053
  destination-port:: TP2054
  destination-port:: TP2055
  destination-port:: TP2056
  destination-port:: TP2057
  destination-port:: TP2058
  destination-port:: TP2059
  destination-port:: TP2060
  destination-port:: TP2061
  destination-port:: TP2062
  destination-port:: TP2063
  destination-port:: TP2064
  destination-port:: TP2065
  destination-port:: TP2066
  destination-port:: TP2067
  destination-port:: TP2068
  destination-port:: TP2069
  destination-port:: TP2070
  destination-port:: TP2071
  destination-port:: TP2072
  destination-port:: TP2073
  destination-port:: TP2074
  destination-port:: TP2075
  destination-port:: TP2076
  destination-port:: TP2077
  destination-port:: TP2078
  destination-port:: TP2079
  destination-port:: TP2080
  destination-port:: TP2081
  destination-port:: TP2082
  destination-port:: TP2083
  destination-port:: TP2084
  destination-port:: TP2085
  destination-port:: TP2086
  destination-port:: TP2087
  destination-port:: TP2088
  destination-port:: TP2089
  destination-port:: TP2090
  destination-port:: TP2091
  destination-port:: TP2092
  destination-port:: TP2093
  destination-port:: TP2094
  destination-port:: TP2095
  destination-port:: TP2096
  destination-port:: TP2097
  destination-port:: TP2098
  destination-port:: TP2099
  destination-port:: TP2100
  destination-port:: TP2101
  destination-port:: TP2102
  destination-port:: TP2103
  destination-port:: TP2104
  destination-port:: TP2105
  destination-port:: TP2106
  destination-port:: TP2107
  destination-port:: TP2108
  destination-port:: TP2109
  destination-port:: TP2110
  destination-port:: TP2111
  destination-port:: TP2112
  destination-port:: TP2113
  destination-port:: TP2114
  destination-port:: TP2115
  destination-port:: TP2116
  destination-port:: TP2117
  destination-port:: TP2118
  destination-port:: TP2119
  destination-port:: TP2120
  destination-port:: TP2121
  destination-port:: TP2122
  destination-port:: TP2123
  destination-port:: TP2124
  destination-port:: TP2125
  destination-port:: TP2126
  destination-port:: TP2127
  destination-port:: TP2128
  destination-port:: TP2129
  destination-port:: TP2130
  destination-port:: TP2131
  destination-port:: TP2132
  destination-port:: TP2133
  destination-port:: TP2134
  destination-port:: TP2135
  destination-port:: TP2136
  destination-port:: TP2137
  destination-port:: TP2138
  destination-port:: TP2139
  destination-port:: TP2140
  destination-port:: TP2141
  destination-port:: TP2142
  destination-port:: TP2143
  destination-port:: TP2144
  destination-port:: TP2145
  destination-port:: TP2146
  destination-port:: TP2147
  destination-port:: TP2148
  destination-port:: TP2149
  destination-port:: TP2150
  destination-port:: TP2151
  destination-port:: TP2152
  destination-port:: TP2153
  destination-port:: TP2154
  destination-port:: TP2155
  destination-port:: TP2156
  destination-port:: TP2157
  destination-port:: TP2158
  destination-port:: TP2159
  destination-port:: TP2160
  destination-port:: TP2161
  destination-port:: TP2162
  destination-port:: TP2163
  destination-port:: TP2164
  destination-port:: TP2165
  destination-port:: TP2166
  destination-port:: TP2167
  destination-port:: TP2168
  destination-port:: TP2169
  destination-port:: TP2170
  destination-port:: TP2171
  destination-port:: TP2172
  destination-port:: TP2173
  destination-port:: TP2174
  destination-port:: TP2175
  destination-port:: TP2176
  destination-port:: TP2177
  destination-port:: TP2178
  destination-port:: TP2179
  destination-port:: TP2180
  destination-port:: TP2181
  destination-port:: TP2182
  destination-port:: TP2183
  destination-port:: TP2184
  destination-port:: TP2185
  destination-port:: TP2186
  destination-port:: TP2187
  destination-port:: TP2188
  destination-port:: TP2189
  destination-port:: TP2190
  destination-port:: TP2191
  destination-port:: TP2192
  destination-port:: TP2193
  destination-port:: TP2194
  destination-port:: TP2195
  destination-port:: TP2196
  destination-port:: TP2197
  destination-port:: TP2198
  destination-port:: TP2199
  destination-port:: TP2200
  destination-port:: TP2201
  destination-port:: TP2202
  destination-port:: TP2203
  destination-port:: TP2204
  destination-port:: TP2205
  destination-port:: TP2206
  destination-port:: TP2207
  destination-port:: TP2208
  destination-port:: TP2209
  destination-port:: TP2210
  destination-port:: TP2211
  destination-port:: TP2212
  destination-port:: TP2213
  destination-port:: TP2214
  destination-port:: TP2215
  destination-port:: TP2216
  destination-port:: TP2217
  destination-port:: TP2218
  destination-port:: TP2219
  destination-port:: TP2220
  destination-port:: TP2221
  destination-port:: TP2222
  destination-port:: TP2223
  destination-port:: TP2224
  destination-port:: TP2225
  destination-port:: TP2226
  destination-port:: TP2227
  destination-port:: TP2228
  destination-port:: TP2229
  destination-port:: TP2230
  destination-port:: TP2231
  destination-port:: TP2232
  destination-port:: TP2233
  destination-port:: TP2234
  destination-port:: TP2235
  destination-port:: TP2236
  destination-port:: TP2237
  destination-port:: TP2238
  destination-port:: TP2239
  destination-port:: TP2240
  destination-port:: TP2241
  destination-port:: TP2242
  destination-port:: TP2243
  destination-port:: TP2244
  destination-port:: TP2245
  destination-port:: TP2246
  destination-port:: TP2247
  destination-port:: TP2248
  destination-port:: TP2249
  destination-port:: TP2250
  destination-port:: TP2251
  destination-port:: TP2252
  destination-port:: TP2253
  destination-port:: TP2254
  destination-port:: TP2255
  destination-port:: TP2256
  destination-port:: TP2257
  destination-port:: TP2258
  destination-port:: TP2259
  protocol:: tcp
  action:: next
}
"""

BAD_TERM_IP_VERSION_MISMATCH = """
term icmpv6-in-inet-term {
  comment:: "Generic description"
  source-address:: INTERNAL
  protocol:: icmpv6
  action:: next
}
"""

BAD_TERM_ICMP_VERSION_MISMATCH = """
term icmp-in-inet6-term {
  comment:: "Generic description"
  source-address:: INTERNAL
  protocol:: icmp
  action:: next
}
"""

BAD_TERM_IGMP_VERSION_MISMATCH = """
term igmp-in-inet6-term {
  comment:: "Generic description"
  source-address:: INTERNAL
  protocol:: igmp
  action:: next
}
"""

BAD_TERM_OPTIONS = """
term term-with-options {
  comment:: "Generic description"
  destination-address:: INTERNAL
  option:: TCP_ESTABLISHED
  action:: next
}
"""

BAD_TERM_NON_VALID_PROJECT_ID = """
term default-deny-ingress-on-target {
  comment:: "Generic description"
  protocol:: tcp
  source-address:: ANY
  action:: deny
  target-resources:: (proj, vpc1)
}
"""

BAD_TERM_NON_VALID_VPC_NAME = """
term default-deny-ingress-on-target {
  comment:: "Generic description"
  protocol:: tcp
  source-address:: ANY
  action:: deny
  target-resources:: (project, Vpc)
}
"""

EXPECTED_ONE_RULE_INGRESS_BETA = """
[
  {
    "displayName": "displayname",
    "type": "FIREWALL",
    "rules": [
      {
        "action": "goto_next",
        "description": "allow-internal-traffic: Generic description",
        "direction": "INGRESS",
        "match": {
          "config": {
            "layer4Configs": [
              {
                "ipProtocol": "tcp"
              },
              {
                "ipProtocol": "icmp"
              },
              {
                "ipProtocol": "udp"
              }
            ],
            "srcIpRanges": ["0.0.0.0/0"]
          },
          "versionedExpr": "FIREWALL"
        },
        "priority": 1,
        "enableLogging": false
      }
    ]
  }
]
"""

EXPECTED_ONE_RULE_INGRESS_W_LOGGING_BETA = """
[
  {
    "displayName": "displayname",
    "type": "FIREWALL",
    "rules": [
      {
        "action": "allow",
        "description": "term-with-logging: Generic description",
        "direction": "INGRESS",
        "match": {
          "config": {
            "layer4Configs": [
              {
                "ipProtocol": "tcp"
              }
            ],
            "srcIpRanges": ["10.0.0.0/8"]
          },
          "versionedExpr": "FIREWALL"
        },
        "priority": 1,
        "enableLogging": true
      }
    ]
  }
]
"""

EXPECTED_ONE_RULE_EGRESS_BETA = """
[
  {
    "displayName": "displayname",
    "type": "FIREWALL",
    "rules": [
      {
        "action": "goto_next",
        "description": "restrict_egress: Generic description",
        "direction": "EGRESS",
        "match": {
          "config": {
            "layer4Configs": [
              {
                "ipProtocol": "tcp"
              },
              {
                "ipProtocol": "icmp"
              },
              {
                "ipProtocol": "udp"
              }
            ],
            "destIpRanges": ["10.0.0.0/8"]
          },
          "versionedExpr": "FIREWALL"
        },
        "priority": 1,
        "enableLogging": false
      }
    ]
  }
]
"""

EXPECTED_MULTIPLE_RULE_INGRESS_BETA = """
[
  {
    "displayName": "displayname",
    "type": "FIREWALL",
    "rules": [
      {
        "action": "goto_next",
        "description": "allow-internal-traffic: Generic description",
        "direction": "INGRESS",
        "enableLogging": false,
        "match": {
          "config": {
            "layer4Configs": [
              {
                "ipProtocol": "tcp"
              },
              {
                "ipProtocol": "icmp"
              },
              {
                "ipProtocol": "udp"
              }
            ],
            "srcIpRanges": ["0.0.0.0/0"]
          },
          "versionedExpr": "FIREWALL"
        },
        "priority": 1
      },
      {
        "action": "goto_next",
        "description": "allow-dns-traffic: Generic description",
        "direction": "INGRESS",
        "enableLogging": false,
        "match": {
          "config": {
            "layer4Configs": [
              {
                "ipProtocol": "tcp",
                "ports": ["53"]
              },
              {
                "ipProtocol": "udp",
                "ports": ["53"]
              }
            ],
            "srcIpRanges": ["0.0.0.0/0"]
          },
          "versionedExpr": "FIREWALL"
        },
        "priority": 2
      }
    ]
  }
]
"""

EXPECTED_MULTIPLE_RULE_INGRESS_W_DENY = """
[
  {
    "displayName": "displayname",
    "type": "FIREWALL",
    "rules": [
      {
        "action": "goto_next",
        "description": "Generic description",
        "direction": "INGRESS",
        "match": {
          "config": {
            "layer4Configs": [
              {
                "ipProtocol": "tcp"
              },
              {
                "ipProtocol": "icmp"
              },
              {
                "ipProtocol": "udp"
              }
            ],
            "srcIpRanges": ["10.0.0.0/8"]
          },
          "versionedExpr": "FIREWALL"
        },
        "priority": 1,
        "enableLogging": false
      },
      {
        "action": "deny",
        "description": "Generic description",
        "direction": "INGRESS",
        "match": {
          "config": {
            "srcIpRanges": ["0.0.0.0/0"]
          },
          "versionedExpr": "FIREWALL"
        },
        "priority": 2,
        "enableLogging": false
      }
    ]
  }
]
"""

EXPECTED_PORT_RANGE_INGRESS_BETA = """
[
  {
    "displayName": "displayname",
    "type": "FIREWALL",
    "rules": [
      {
        "action": "goto_next",
        "description": "allow-port-range: Generic description",
        "direction": "INGRESS",
        "match": {
          "config": {
            "layer4Configs": [
              {
                "ipProtocol": "tcp",
                "ports": ["8000-9000"]
              }
            ],
            "srcIpRanges": ["10.0.0.0/8"]
          },
          "versionedExpr": "FIREWALL"
        },
        "priority": 1,
        "enableLogging": false
      }
    ]
  }
]
"""

EXPECTED_DENY_INGRESS_BETA = """
[
  {
    "displayName": "displayname",
    "type": "FIREWALL",
    "rules": [
      {
        "action": "deny",
        "description": "default-deny-ingress: Generic description",
        "direction": "INGRESS",
        "match": {
          "config": {
            "layer4Configs": [
              {
                "ipProtocol": "all"
              }
            ],
            "srcIpRanges": ["0.0.0.0/0"]
          },
          "versionedExpr": "FIREWALL"
        },
        "priority": 1,
        "enableLogging": false
      }
    ]
  }
]
"""

EXPECTED_IPV6_DENY_INGRESS_GA = """
[
  {
    "shortName": "displayname",
    "type": "FIREWALL",
    "rules": [
      {
        "action": "deny",
        "description": "default-deny-ingress: Generic description",
        "direction": "INGRESS",
        "match": {
          "layer4Configs": [
            {
              "ipProtocol": "all"
            }
          ],
          "srcIpRanges": ["::/0"],
          "versionedExpr": "FIREWALL"
        },
        "priority": 1,
        "enableLogging": false
      }
    ]
  }
]
"""

EXPECTED_MIXED_DENY_INGRESS_GA = """
[
  {
    "shortName": "displayname",
    "type": "FIREWALL",
    "rules": [
      {
        "action": "deny",
        "description": "default-deny-ingress: Generic description",
        "direction": "INGRESS",
        "match": {
          "layer4Configs": [
            {
              "ipProtocol": "all"
            }
          ],
          "srcIpRanges": ["0.0.0.0/0"],
          "versionedExpr": "FIREWALL"
        },
        "priority": 1,
        "enableLogging": false
      },
      {
        "action": "deny",
        "description": "default-deny-ingress-v6: Generic description",
        "direction": "INGRESS",
        "match": {
          "layer4Configs": [
            {
              "ipProtocol": "all"
            }
          ],
          "srcIpRanges": ["::/0"],
          "versionedExpr": "FIREWALL"
        },
        "priority": 2,
        "enableLogging": false
      }
    ]
  }
]
"""

EXPECTED_DENY_INGRESS_ON_TARGET_BETA = """
[
  {
    "displayName": "displayname",
    "type": "FIREWALL",
    "rules": [
      {
        "action": "deny",
        "description": "default-deny-ingress-on-target: Generic description",
        "direction": "INGRESS",
        "match": {
          "config": {
            "layer4Configs": [
              {
                "ipProtocol": "all"
              }
            ],
            "srcIpRanges": ["0.0.0.0/0"]
          },
          "versionedExpr": "FIREWALL"
        },
        "priority": 1,
        "enableLogging": false,
        "targetResources": ["https://www.googleapis.com/compute/v1/projects/project1/global/networks/vpc1",
                            "https://www.googleapis.com/compute/v1/projects/project2/global/networks/vpc2"]
      }
    ]
  }
]
"""

EXPECTED_INGRESS_AND_EGRESS_W_DENY_BETA = """
[
  {
    "displayName": "displayname",
    "type": "FIREWALL",
    "rules": [
      {
        "action": "goto_next",
        "description": "allow-internal-traffic: Generic description",
        "direction": "INGRESS",
        "match": {
          "config": {
            "layer4Configs": [
              {
                "ipProtocol": "tcp"
              },
              {
                "ipProtocol": "icmp"
              },
              {
                "ipProtocol": "udp"
              }
            ],
            "srcIpRanges": ["0.0.0.0/0"]
          },
          "versionedExpr": "FIREWALL"
        },
        "priority": 1,
        "enableLogging": false
      },
      {
        "action": "deny",
        "description": "default-deny-ingress: Generic description",
        "direction": "INGRESS",
        "match": {
          "config": {
            "layer4Configs": [
              {
                "ipProtocol": "all"
              }
            ],
            "srcIpRanges": ["0.0.0.0/0"]
          },
          "versionedExpr": "FIREWALL"
        },
        "priority": 2,
        "enableLogging": false
      },
      {
        "action": "goto_next",
        "description": "restrict_egress: Generic description",
        "direction": "EGRESS",
        "match": {
          "config": {
            "layer4Configs": [
              {
                "ipProtocol": "tcp"
              },
              {
                "ipProtocol": "icmp"
              },
              {
                "ipProtocol": "udp"
              }
            ],
            "destIpRanges": ["0.0.0.0/0"]
          },
          "versionedExpr": "FIREWALL"
        },
        "priority": 3,
        "enableLogging": false
      },
      {
        "action": "deny",
        "description": "default-deny-egress: Generic description",
        "direction": "EGRESS",
        "match": {
          "config": {
            "destIpRanges": ["0.0.0.0/0"],
            "layer4Configs": [
              {
                "ipProtocol": "all"
              }
            ]
          },
          "versionedExpr": "FIREWALL"
        },
        "priority": 4,
        "enableLogging": false
      }
    ]
  }
]
"""

EXPECTED_DENY_EGRESS_BETA = """
[
  {
    "displayName": "displayname",
    "type": "FIREWALL",
    "rules": [
      {
        "action": "deny",
        "description": "default-deny-egress: Generic description",
        "direction": "EGRESS",
        "match": {
          "config": {
            "destIpRanges": ["0.0.0.0/0"],
            "layer4Configs": [
              {
                "ipProtocol": "all"
              }
            ]
          },
          "versionedExpr": "FIREWALL"
        },
        "priority": 1,
        "enableLogging": false
      }
    ]
  }
]
"""

EXPECTED_IPV6_DENY_EGRESS_GA = """
[
  {
    "shortName": "displayname",
    "type": "FIREWALL",
    "rules": [
      {
        "action": "deny",
        "description": "default-deny-egress: Generic description",
        "direction": "EGRESS",
        "match": {
          "destIpRanges": ["::/0"],
          "layer4Configs": [
            {
              "ipProtocol": "all"
            }
          ],
          "versionedExpr": "FIREWALL"
        },
        "priority": 1,
        "enableLogging": false
      }
    ]
  }
]
"""

EXPECTED_MIXED_DENY_EGRESS_GA = """
[
  {
    "shortName": "displayname",
    "type": "FIREWALL",
    "rules": [
      {
        "action": "deny",
        "description": "default-deny-egress: Generic description",
        "direction": "EGRESS",
        "match": {
          "destIpRanges": ["0.0.0.0/0"],
          "layer4Configs": [
            {
              "ipProtocol": "all"
            }
          ],
          "versionedExpr": "FIREWALL"
        },
        "priority": 1,
        "enableLogging": false
      },
      {
        "action": "deny",
        "description": "default-deny-egress-v6: Generic description",
        "direction": "EGRESS",
        "match": {
          "destIpRanges": ["::/0"],
          "layer4Configs": [
            {
              "ipProtocol": "all"
            }
          ],
          "versionedExpr": "FIREWALL"
        },
        "priority": 2,
        "enableLogging": false
      }
    ]
  }
]
"""

EXPECTED_COST_OF_ONE = """
[
  {
    "displayName": "displayname",
    "type": "FIREWALL",
    "rules": [
      {
        "action": "goto_next",
        "description": "allow-traffic-to-port: Generic description",
        "direction": "INGRESS",
        "enableLogging": false,
        "match": {
          "config": {
            "layer4Configs": [
              {
                "ipProtocol": "tcp",
                "ports": ["80"]
              }
            ],
            "srcIpRanges": ["10.1.1.0/24"]/t
          },
          "versionedExpr": "FIREWALL"
        },
        "priority": 1
      }
    ]
  }
]
"""

EXPECTED_CHUNKED_BETA = """
[
  {
    "displayName": "displayname",
    "type": "FIREWALL",
    "rules": [
      {
        "action": "goto_next",
        "description": "allow-traffic-to-port: Generic description",
        "direction": "INGRESS",
        "enableLogging": false,
        "match": {
          "config": {
            "layer4Configs": [
              {
                "ipProtocol": "tcp",
                "ports": ["80"]
              }
            ],
            "srcIpRanges": [
              "10.0.0.1/32",
              "10.0.1.1/32",
              "192.168.0.0/32",
              "192.168.1.0/32",
              "192.168.2.0/32",
              "192.168.3.0/32",
              "192.168.4.0/32",
              "192.168.5.0/32",
              "192.168.6.0/32",
              "192.168.7.0/32",
              "192.168.8.0/32",
              "192.168.9.0/32",
              "192.168.10.0/32",
              "192.168.11.0/32",
              "192.168.12.0/32",
              "192.168.13.0/32",
              "192.168.14.0/32",
              "192.168.15.0/32",
              "192.168.16.0/32",
              "192.168.17.0/32",
              "192.168.18.0/32",
              "192.168.19.0/32",
              "192.168.20.0/32",
              "192.168.21.0/32",
              "192.168.22.0/32",
              "192.168.23.0/32",
              "192.168.24.0/32",
              "192.168.25.0/32",
              "192.168.26.0/32",
              "192.168.27.0/32",
              "192.168.28.0/32",
              "192.168.29.0/32",
              "192.168.30.0/32",
              "192.168.31.0/32",
              "192.168.32.0/32",
              "192.168.33.0/32",
              "192.168.34.0/32",
              "192.168.35.0/32",
              "192.168.36.0/32",
              "192.168.37.0/32",
              "192.168.38.0/32",
              "192.168.39.0/32",
              "192.168.40.0/32",
              "192.168.41.0/32",
              "192.168.42.0/32",
              "192.168.43.0/32",
              "192.168.44.0/32",
              "192.168.45.0/32",
              "192.168.46.0/32",
              "192.168.47.0/32",
              "192.168.48.0/32",
              "192.168.49.0/32",
              "192.168.50.0/32",
              "192.168.51.0/32",
              "192.168.52.0/32",
              "192.168.53.0/32",
              "192.168.54.0/32",
              "192.168.55.0/32",
              "192.168.56.0/32",
              "192.168.57.0/32",
              "192.168.58.0/32",
              "192.168.59.0/32",
              "192.168.60.0/32",
              "192.168.61.0/32",
              "192.168.62.0/32",
              "192.168.63.0/32",
              "192.168.64.0/32",
              "192.168.65.0/32",
              "192.168.66.0/32",
              "192.168.67.0/32",
              "192.168.68.0/32",
              "192.168.69.0/32",
              "192.168.70.0/32",
              "192.168.71.0/32",
              "192.168.72.0/32",
              "192.168.73.0/32",
              "192.168.74.0/32",
              "192.168.75.0/32",
              "192.168.76.0/32",
              "192.168.77.0/32",
              "192.168.78.0/32",
              "192.168.79.0/32",
              "192.168.80.0/32",
              "192.168.81.0/32",
              "192.168.82.0/32",
              "192.168.83.0/32",
              "192.168.84.0/32",
              "192.168.85.0/32",
              "192.168.86.0/32",
              "192.168.87.0/32",
              "192.168.88.0/32",
              "192.168.89.0/32",
              "192.168.90.0/32",
              "192.168.91.0/32",
              "192.168.92.0/32",
              "192.168.93.0/32",
              "192.168.94.0/32",
              "192.168.95.0/32",
              "192.168.96.0/32",
              "192.168.97.0/32",
              "192.168.98.0/32",
              "192.168.99.0/32",
              "192.168.100.0/32",
              "192.168.101.0/32",
              "192.168.102.0/32",
              "192.168.103.0/32",
              "192.168.104.0/32",
              "192.168.105.0/32",
              "192.168.106.0/32",
              "192.168.107.0/32",
              "192.168.108.0/32",
              "192.168.109.0/32",
              "192.168.110.0/32",
              "192.168.111.0/32",
              "192.168.112.0/32",
              "192.168.113.0/32",
              "192.168.114.0/32",
              "192.168.115.0/32",
              "192.168.116.0/32",
              "192.168.117.0/32",
              "192.168.118.0/32",
              "192.168.119.0/32",
              "192.168.120.0/32",
              "192.168.121.0/32",
              "192.168.122.0/32",
              "192.168.123.0/32",
              "192.168.124.0/32",
              "192.168.125.0/32",
              "192.168.126.0/32",
              "192.168.127.0/32",
              "192.168.128.0/32",
              "192.168.129.0/32",
              "192.168.130.0/32",
              "192.168.131.0/32",
              "192.168.132.0/32",
              "192.168.133.0/32",
              "192.168.134.0/32",
              "192.168.135.0/32",
              "192.168.136.0/32",
              "192.168.137.0/32",
              "192.168.138.0/32",
              "192.168.139.0/32",
              "192.168.140.0/32",
              "192.168.141.0/32",
              "192.168.142.0/32",
              "192.168.143.0/32",
              "192.168.144.0/32",
              "192.168.145.0/32",
              "192.168.146.0/32",
              "192.168.147.0/32",
              "192.168.148.0/32",
              "192.168.149.0/32",
              "192.168.150.0/32",
              "192.168.151.0/32",
              "192.168.152.0/32",
              "192.168.153.0/32",
              "192.168.154.0/32",
              "192.168.155.0/32",
              "192.168.156.0/32",
              "192.168.157.0/32",
              "192.168.158.0/32",
              "192.168.159.0/32",
              "192.168.160.0/32",
              "192.168.161.0/32",
              "192.168.162.0/32",
              "192.168.163.0/32",
              "192.168.164.0/32",
              "192.168.165.0/32",
              "192.168.166.0/32",
              "192.168.167.0/32",
              "192.168.168.0/32",
              "192.168.169.0/32",
              "192.168.170.0/32",
              "192.168.171.0/32",
              "192.168.172.0/32",
              "192.168.173.0/32",
              "192.168.174.0/32",
              "192.168.175.0/32",
              "192.168.176.0/32",
              "192.168.177.0/32",
              "192.168.178.0/32",
              "192.168.179.0/32",
              "192.168.180.0/32",
              "192.168.181.0/32",
              "192.168.182.0/32",
              "192.168.183.0/32",
              "192.168.184.0/32",
              "192.168.185.0/32",
              "192.168.186.0/32",
              "192.168.187.0/32",
              "192.168.188.0/32",
              "192.168.189.0/32",
              "192.168.190.0/32",
              "192.168.191.0/32",
              "192.168.192.0/32",
              "192.168.193.0/32",
              "192.168.194.0/32",
              "192.168.195.0/32",
              "192.168.196.0/32",
              "192.168.197.0/32",
              "192.168.198.0/32",
              "192.168.199.0/32",
              "192.168.200.0/32",
              "192.168.201.0/32",
              "192.168.202.0/32",
              "192.168.203.0/32",
              "192.168.204.0/32",
              "192.168.205.0/32",
              "192.168.206.0/32",
              "192.168.207.0/32",
              "192.168.208.0/32",
              "192.168.209.0/32",
              "192.168.210.0/32",
              "192.168.211.0/32",
              "192.168.212.0/32",
              "192.168.213.0/32",
              "192.168.214.0/32",
              "192.168.215.0/32",
              "192.168.216.0/32",
              "192.168.217.0/32",
              "192.168.218.0/32",
              "192.168.219.0/32",
              "192.168.220.0/32",
              "192.168.221.0/32",
              "192.168.222.0/32",
              "192.168.223.0/32",
              "192.168.224.0/32",
              "192.168.225.0/32",
              "192.168.226.0/32",
              "192.168.227.0/32",
              "192.168.228.0/32",
              "192.168.229.0/32",
              "192.168.230.0/32",
              "192.168.231.0/32",
              "192.168.232.0/32",
              "192.168.233.0/32",
              "192.168.234.0/32",
              "192.168.235.0/32",
              "192.168.236.0/32",
              "192.168.237.0/32",
              "192.168.238.0/32",
              "192.168.239.0/32",
              "192.168.240.0/32",
              "192.168.241.0/32",
              "192.168.242.0/32",
              "192.168.243.0/32",
              "192.168.244.0/32",
              "192.168.245.0/32",
              "192.168.246.0/32",
              "192.168.247.0/32",
              "192.168.248.0/32",
              "192.168.249.0/32",
              "192.168.250.0/32",
              "192.168.251.0/32",
              "192.168.252.0/32",
              "192.168.253.0/32"
            ]
          },
          "versionedExpr": "FIREWALL"
        },
        "priority": 1
      },
      {
        "action": "goto_next",
        "description": "allow-traffic-to-port: Generic description",
        "direction": "INGRESS",
        "enableLogging": false,
        "match": {
          "config": {
            "layer4Configs": [
              {
                "ipProtocol": "tcp",
                "ports": ["80"]
              }
            ],
            "srcIpRanges": [
              "192.168.254.0/32",
              "192.168.255.0/32"
            ]
          },
          "versionedExpr": "FIREWALL"
        },
        "priority": 2
      }
    ]
  }
]
"""

EXPECTED_EGRESS_CHUNKED_BETA = """
[
  {
    "displayName": "displayname",
    "type": "FIREWALL",
    "rules": [
      {
        "action": "goto_next",
        "description": "allow-traffic-to-port: Generic description",
        "direction": "EGRESS",
        "enableLogging": false,
        "match": {
          "config": {
            "layer4Configs": [
              {
                "ipProtocol": "tcp",
                "ports": ["80"]
              }
            ],
            "destIpRanges": [
              "10.0.0.1/32",
              "10.0.1.1/32",
              "192.168.0.0/32",
              "192.168.1.0/32",
              "192.168.2.0/32",
              "192.168.3.0/32",
              "192.168.4.0/32",
              "192.168.5.0/32",
              "192.168.6.0/32",
              "192.168.7.0/32",
              "192.168.8.0/32",
              "192.168.9.0/32",
              "192.168.10.0/32",
              "192.168.11.0/32",
              "192.168.12.0/32",
              "192.168.13.0/32",
              "192.168.14.0/32",
              "192.168.15.0/32",
              "192.168.16.0/32",
              "192.168.17.0/32",
              "192.168.18.0/32",
              "192.168.19.0/32",
              "192.168.20.0/32",
              "192.168.21.0/32",
              "192.168.22.0/32",
              "192.168.23.0/32",
              "192.168.24.0/32",
              "192.168.25.0/32",
              "192.168.26.0/32",
              "192.168.27.0/32",
              "192.168.28.0/32",
              "192.168.29.0/32",
              "192.168.30.0/32",
              "192.168.31.0/32",
              "192.168.32.0/32",
              "192.168.33.0/32",
              "192.168.34.0/32",
              "192.168.35.0/32",
              "192.168.36.0/32",
              "192.168.37.0/32",
              "192.168.38.0/32",
              "192.168.39.0/32",
              "192.168.40.0/32",
              "192.168.41.0/32",
              "192.168.42.0/32",
              "192.168.43.0/32",
              "192.168.44.0/32",
              "192.168.45.0/32",
              "192.168.46.0/32",
              "192.168.47.0/32",
              "192.168.48.0/32",
              "192.168.49.0/32",
              "192.168.50.0/32",
              "192.168.51.0/32",
              "192.168.52.0/32",
              "192.168.53.0/32",
              "192.168.54.0/32",
              "192.168.55.0/32",
              "192.168.56.0/32",
              "192.168.57.0/32",
              "192.168.58.0/32",
              "192.168.59.0/32",
              "192.168.60.0/32",
              "192.168.61.0/32",
              "192.168.62.0/32",
              "192.168.63.0/32",
              "192.168.64.0/32",
              "192.168.65.0/32",
              "192.168.66.0/32",
              "192.168.67.0/32",
              "192.168.68.0/32",
              "192.168.69.0/32",
              "192.168.70.0/32",
              "192.168.71.0/32",
              "192.168.72.0/32",
              "192.168.73.0/32",
              "192.168.74.0/32",
              "192.168.75.0/32",
              "192.168.76.0/32",
              "192.168.77.0/32",
              "192.168.78.0/32",
              "192.168.79.0/32",
              "192.168.80.0/32",
              "192.168.81.0/32",
              "192.168.82.0/32",
              "192.168.83.0/32",
              "192.168.84.0/32",
              "192.168.85.0/32",
              "192.168.86.0/32",
              "192.168.87.0/32",
              "192.168.88.0/32",
              "192.168.89.0/32",
              "192.168.90.0/32",
              "192.168.91.0/32",
              "192.168.92.0/32",
              "192.168.93.0/32",
              "192.168.94.0/32",
              "192.168.95.0/32",
              "192.168.96.0/32",
              "192.168.97.0/32",
              "192.168.98.0/32",
              "192.168.99.0/32",
              "192.168.100.0/32",
              "192.168.101.0/32",
              "192.168.102.0/32",
              "192.168.103.0/32",
              "192.168.104.0/32",
              "192.168.105.0/32",
              "192.168.106.0/32",
              "192.168.107.0/32",
              "192.168.108.0/32",
              "192.168.109.0/32",
              "192.168.110.0/32",
              "192.168.111.0/32",
              "192.168.112.0/32",
              "192.168.113.0/32",
              "192.168.114.0/32",
              "192.168.115.0/32",
              "192.168.116.0/32",
              "192.168.117.0/32",
              "192.168.118.0/32",
              "192.168.119.0/32",
              "192.168.120.0/32",
              "192.168.121.0/32",
              "192.168.122.0/32",
              "192.168.123.0/32",
              "192.168.124.0/32",
              "192.168.125.0/32",
              "192.168.126.0/32",
              "192.168.127.0/32",
              "192.168.128.0/32",
              "192.168.129.0/32",
              "192.168.130.0/32",
              "192.168.131.0/32",
              "192.168.132.0/32",
              "192.168.133.0/32",
              "192.168.134.0/32",
              "192.168.135.0/32",
              "192.168.136.0/32",
              "192.168.137.0/32",
              "192.168.138.0/32",
              "192.168.139.0/32",
              "192.168.140.0/32",
              "192.168.141.0/32",
              "192.168.142.0/32",
              "192.168.143.0/32",
              "192.168.144.0/32",
              "192.168.145.0/32",
              "192.168.146.0/32",
              "192.168.147.0/32",
              "192.168.148.0/32",
              "192.168.149.0/32",
              "192.168.150.0/32",
              "192.168.151.0/32",
              "192.168.152.0/32",
              "192.168.153.0/32",
              "192.168.154.0/32",
              "192.168.155.0/32",
              "192.168.156.0/32",
              "192.168.157.0/32",
              "192.168.158.0/32",
              "192.168.159.0/32",
              "192.168.160.0/32",
              "192.168.161.0/32",
              "192.168.162.0/32",
              "192.168.163.0/32",
              "192.168.164.0/32",
              "192.168.165.0/32",
              "192.168.166.0/32",
              "192.168.167.0/32",
              "192.168.168.0/32",
              "192.168.169.0/32",
              "192.168.170.0/32",
              "192.168.171.0/32",
              "192.168.172.0/32",
              "192.168.173.0/32",
              "192.168.174.0/32",
              "192.168.175.0/32",
              "192.168.176.0/32",
              "192.168.177.0/32",
              "192.168.178.0/32",
              "192.168.179.0/32",
              "192.168.180.0/32",
              "192.168.181.0/32",
              "192.168.182.0/32",
              "192.168.183.0/32",
              "192.168.184.0/32",
              "192.168.185.0/32",
              "192.168.186.0/32",
              "192.168.187.0/32",
              "192.168.188.0/32",
              "192.168.189.0/32",
              "192.168.190.0/32",
              "192.168.191.0/32",
              "192.168.192.0/32",
              "192.168.193.0/32",
              "192.168.194.0/32",
              "192.168.195.0/32",
              "192.168.196.0/32",
              "192.168.197.0/32",
              "192.168.198.0/32",
              "192.168.199.0/32",
              "192.168.200.0/32",
              "192.168.201.0/32",
              "192.168.202.0/32",
              "192.168.203.0/32",
              "192.168.204.0/32",
              "192.168.205.0/32",
              "192.168.206.0/32",
              "192.168.207.0/32",
              "192.168.208.0/32",
              "192.168.209.0/32",
              "192.168.210.0/32",
              "192.168.211.0/32",
              "192.168.212.0/32",
              "192.168.213.0/32",
              "192.168.214.0/32",
              "192.168.215.0/32",
              "192.168.216.0/32",
              "192.168.217.0/32",
              "192.168.218.0/32",
              "192.168.219.0/32",
              "192.168.220.0/32",
              "192.168.221.0/32",
              "192.168.222.0/32",
              "192.168.223.0/32",
              "192.168.224.0/32",
              "192.168.225.0/32",
              "192.168.226.0/32",
              "192.168.227.0/32",
              "192.168.228.0/32",
              "192.168.229.0/32",
              "192.168.230.0/32",
              "192.168.231.0/32",
              "192.168.232.0/32",
              "192.168.233.0/32",
              "192.168.234.0/32",
              "192.168.235.0/32",
              "192.168.236.0/32",
              "192.168.237.0/32",
              "192.168.238.0/32",
              "192.168.239.0/32",
              "192.168.240.0/32",
              "192.168.241.0/32",
              "192.168.242.0/32",
              "192.168.243.0/32",
              "192.168.244.0/32",
              "192.168.245.0/32",
              "192.168.246.0/32",
              "192.168.247.0/32",
              "192.168.248.0/32",
              "192.168.249.0/32",
              "192.168.250.0/32",
              "192.168.251.0/32",
              "192.168.252.0/32",
              "192.168.253.0/32"
            ]
          },
          "versionedExpr": "FIREWALL"
        },
        "priority": 1
      },
      {
        "action": "goto_next",
        "description": "allow-traffic-to-port: Generic description",
        "direction": "EGRESS",
        "enableLogging": false,
        "match": {
          "config": {
            "layer4Configs": [
              {
                "ipProtocol": "tcp",
                "ports": ["80"]
              }
            ],
            "destIpRanges": [
              "192.168.254.0/32",
              "192.168.255.0/32"
            ]
          },
          "versionedExpr": "FIREWALL"
        },
        "priority": 2
      }
    ]
  }
]
"""

EXPECTED_ONE_RULE_NUMBERED_PROTOCOL_BETA = """
[
  {
    "displayName": "displayname",
    "type": "FIREWALL",
    "rules": [
      {
        "action": "goto_next",
        "description": "term-numbered-protocol: Generic description",
        "direction": "INGRESS",
        "match": {
          "config": {
            "layer4Configs": [
              {
                "ipProtocol": "2"
              }
            ],
            "srcIpRanges": ["0.0.0.0/0"]
          },
          "versionedExpr": "FIREWALL"
        },
        "priority": 1,
        "enableLogging": false
      }
    ]
  }
]
"""

EXPECTED_ONE_RULE_IPV6_PROTOCOL_GA = """
[
  {
    "shortName": "displayname",
    "type": "FIREWALL",
    "rules": [
      {
        "action": "goto_next",
        "description": "allow-traffic-to-port: Generic description",
        "direction": "INGRESS",
        "match": {
          "layer4Configs": [
            {
              "ipProtocol": "tcp",
              "ports": ["80"]
            }
          ],
          "srcIpRanges": ["2001:4860:8000::5/128"],
          "versionedExpr": "FIREWALL"
        },
        "priority": 1,
        "enableLogging": false
      }
    ]
  }
]
"""

EXPECTED_ONE_RULE_MIXED_IPV6_PROTOCOL_GA = """
[
  {
    "shortName": "displayname",
    "type": "FIREWALL",
    "rules": [
      {
        "action": "goto_next",
        "description": "allow-traffic-to-port-v6: Generic description",
        "direction": "INGRESS",
        "match": {
          "layer4Configs": [
            {
              "ipProtocol": "tcp",
              "ports": ["80"]
            }
          ],
          "srcIpRanges": ["2001:4860:8000::5/128"],
          "versionedExpr": "FIREWALL"
        },
        "priority": 1,
        "enableLogging": false
      }
    ]
  }
]
"""

EXPECTED_ONE_RULE_MIXED_IPV4_PROTOCOL_GA = """
[
  {
    "shortName": "displayname",
    "type": "FIREWALL",
    "rules": [
      {
        "action": "goto_next",
        "description": "allow-traffic-to-port: Generic description",
        "direction": "INGRESS",
        "match": {
          "layer4Configs": [
            {
              "ipProtocol": "tcp",
              "ports": ["80"]
            }
          ],
          "srcIpRanges": ["10.0.0.0/8"],
          "versionedExpr": "FIREWALL"
        },
        "priority": 1,
        "enableLogging": false
      }
    ]
  }
]
"""

EXPECTED_MULTIPLE_MIXED_RULE_INGRESS_GA = """
[
  {
    "shortName": "displayname",
    "type": "FIREWALL",
    "rules": [
      {
        "action": "goto_next",
        "description": "allow-traffic-to-port: Generic description",
        "direction": "INGRESS",
        "enableLogging": false,
        "match": {
          "layer4Configs": [
            {
              "ipProtocol": "tcp",
              "ports": ["80"]
            }
          ],
          "srcIpRanges": ["10.0.0.0/8"],
          "versionedExpr": "FIREWALL"
        },
        "priority": 1
      },
      {
        "action": "goto_next",
        "description": "allow-traffic-to-port-v6: Generic description",
        "direction": "INGRESS",
        "enableLogging": false,
        "match": {
          "layer4Configs": [
            {
              "ipProtocol": "tcp",
              "ports": ["80"]
            }
          ],
          "srcIpRanges": ["2001:4860:8000::5/128"],
          "versionedExpr": "FIREWALL"
        },
        "priority": 2
      }
    ]
  }
]
"""

EXPECTED_MULTIPLE_MIXED_RULE_INGRESS_WITH_ICMP_GA = """
[
  {
    "shortName": "displayname",
    "type": "FIREWALL",
    "rules": [
      {
        "action": "goto_next",
        "description": "allow-internal-traffic: Generic description",
        "direction": "INGRESS",
        "enableLogging": false,
        "match": {
          "layer4Configs": [
            {
              "ipProtocol": "tcp"
            },
            {
              "ipProtocol": "icmp"
            },
            {
              "ipProtocol": "udp"
            }
          ],
          "srcIpRanges": ["10.0.0.0/8"],
          "versionedExpr": "FIREWALL"
        },
        "priority": 1
      },
      {
        "action": "goto_next",
        "description": "allow-internal-traffic-v6: Generic description",
        "direction": "INGRESS",
        "enableLogging": false,
        "match": {
          "layer4Configs": [
            {
              "ipProtocol": "tcp"
            },
            {
              "ipProtocol": "udp"
            }
          ],
          "srcIpRanges": ["2001:4860:8000::5/128"],
          "versionedExpr": "FIREWALL"
        },
        "priority": 2
      }
    ]
  }
]
"""

EXPECTED_MULTIPLE_MIXED_RULE_INGRESS_WITH_ICMPV6_GA = """
[
  {
    "shortName": "displayname",
    "type": "FIREWALL",
    "rules": [
      {
        "action": "goto_next",
        "description": "allow-internal-traffic: Generic description",
        "direction": "INGRESS",
        "enableLogging": false,
        "match": {
          "layer4Configs": [
            {
              "ipProtocol": "tcp"
            },
            {
              "ipProtocol": "udp"
            }
          ],
          "srcIpRanges": ["10.0.0.0/8"],
          "versionedExpr": "FIREWALL"
        },
        "priority": 1
      },
      {
        "action": "goto_next",
        "description": "allow-internal-traffic-v6: Generic description",
        "direction": "INGRESS",
        "enableLogging": false,
        "match": {
          "layer4Configs": [
            {
              "ipProtocol": "tcp"
            },
            {
              "ipProtocol": "58"
            },
            {
              "ipProtocol": "udp"
            }
          ],
          "srcIpRanges": ["2001:4860:8000::5/128"],
          "versionedExpr": "FIREWALL"
        },
        "priority": 2
      }
    ]
  }
]
"""

SUPPORTED_TOKENS = frozenset({
    'action',
    'comment',
    'destination_address',
    'destination_port',
    'destination_tag',
    'logging',
    'name',
    'option',
    'protocol',
    'source_address',
    'source_port',
    'source_tag',
    'stateless_reply',
    'target_resources',
    'translated',
    'platform',
    'platform_exclude',
})

SUPPORTED_SUB_TOKENS = {
    'action': {
        'accept', 'deny', 'next'
    }
}

EXP_INFO = 2

TEST_IP = [nacaddr.IP('10.0.0.0/8')]
TEST_IPV6_IP = [
    nacaddr.IP('2001:4860:8000::5/128'),
    nacaddr.IP('::ffff:a02:301/128'),  # IPv4-mapped
    nacaddr.IP('2002::/16'),  # 6to4
    nacaddr.IP('::0000:a02:301/128'),  # IPv4-compatible
]
TEST_MIXED_IPS = [
    nacaddr.IP('10.0.0.0/8'),
    nacaddr.IP('2001:4860:8000::5/128'),
    nacaddr.IP('::ffff:a02:301/128'),  # IPv4-mapped
    nacaddr.IP('2002::/16'),  # 6to4
    nacaddr.IP('::0000:a02:301/128'),  # IPv4-compatible
]
ALL_IPV4_IPS = [nacaddr.IP('0.0.0.0/0')]
ALL_IPV6_IPS = [nacaddr.IP('::/0')]
MANY_IPS = [nacaddr.IP('192.168.' + str(x) +'.0/32') for x in range(
    0, 256)]
MANY_IPS.extend([nacaddr.IP('10.0.0.1'), nacaddr.IP('10.0.1.1')])


class GcpHfTest(parameterized.TestCase):

  def setUp(self):
    super().setUp()
    self.naming = mock.create_autospec(naming.Naming)

  def _StripAclHeaders(self, acl):
    return '\n'.join([line for line in str(acl).split('\n')
                      if not line.lstrip().startswith('#')])

  def testDefaultHeader(self):
    """Test that a header without options is accepted."""
    self.naming.GetNetAddr.return_value = ALL_IPV4_IPS

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_NO_OPTIONS + TERM_ALLOW_ALL_INTERNAL,
                           self.naming),
        EXP_INFO)
    expected = json.loads(EXPECTED_ONE_RULE_INGRESS_BETA)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testOptionMaxHeader(self):
    """Test that a header with a default maximum cost is accepted."""
    self.naming.GetNetAddr.return_value = ALL_IPV4_IPS

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_OPTION_MAX + TERM_ALLOW_ALL_INTERNAL,
                           self.naming),
        EXP_INFO)
    expected = json.loads(EXPECTED_ONE_RULE_INGRESS_BETA)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testOptionEgressHeader(self):
    """Test that a header with direction is accepted."""
    self.naming.GetNetAddr.return_value = TEST_IP

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_OPTION_EGRESS + TERM_RESTRICT_EGRESS,
                           self.naming),
        EXP_INFO)
    expected = json.loads(EXPECTED_ONE_RULE_EGRESS_BETA)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testOptionAFHeader(self):
    """Test that a header with address family is accepted."""
    self.naming.GetNetAddr.return_value = ALL_IPV4_IPS

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_OPTION_AF + TERM_ALLOW_ALL_INTERNAL,
                           self.naming),
        EXP_INFO)
    expected = json.loads(EXPECTED_ONE_RULE_INGRESS_BETA)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testOptionEgressAndMaxHeader(self):
    """Test a header with direction and default maximum cost is accepted."""
    self.naming.GetNetAddr.return_value = TEST_IP

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_OPTION_EGRESS_AND_MAX + TERM_RESTRICT_EGRESS,
                           self.naming),
        EXP_INFO)
    expected = json.loads(EXPECTED_ONE_RULE_EGRESS_BETA)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testOptionEgressAndAF(self):
    """Test a header with a direction and address family is accepted."""
    self.naming.GetNetAddr.return_value = TEST_IP

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_OPTION_EGRESS_AND_AF + TERM_RESTRICT_EGRESS,
                           self.naming),
        EXP_INFO)
    expected = json.loads(EXPECTED_ONE_RULE_EGRESS_BETA)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testOptionMaxAndAF(self):
    """Test a header with default maximum cost & address family is accepted."""
    self.naming.GetNetAddr.return_value = ALL_IPV4_IPS

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_OPTION_MAX_AND_AF + TERM_ALLOW_ALL_INTERNAL,
                           self.naming),
        EXP_INFO)
    expected = json.loads(EXPECTED_ONE_RULE_INGRESS_BETA)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testOptionApiVersionAFHeader(self):
    """Test that a header with api_version is accepted."""
    self.naming.GetNetAddr.return_value = ALL_IPV4_IPS

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_OPTION_BETA + TERM_ALLOW_ALL_INTERNAL,
                           self.naming), EXP_INFO)
    expected = json.loads(EXPECTED_ONE_RULE_INGRESS_BETA)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testRaisesHeaderErrorOnUnknownOption(self):
    """Test that an unknown header option raises a HeaderError."""
    with self.assertRaises(gcp.HeaderError):
      gcp_hf.HierarchicalFirewall(
          policy.ParsePolicy(BAD_HEADER_UNKNOWN_OPTION
                             + TERM_ALLOW_ALL_INTERNAL,
                             self.naming),
          EXP_INFO)

  def testRaisesHeaderErrorOnUnknownDirection(self):
    """Test that an unknown direction option raises a HeaderError."""
    with self.assertRaises(gcp.HeaderError):
      gcp_hf.HierarchicalFirewall(
          policy.ParsePolicy(BAD_HEADER_UNKNOWN_DIRECTION
                             + TERM_ALLOW_ALL_INTERNAL,
                             self.naming),
          EXP_INFO)

  def testRaisesHeaderErrorOnInvalidMaxCost(self):
    """Test that a maximum default cost over 2^16 raises a HeaderError."""
    with self.assertRaises(gcp.HeaderError):
      gcp_hf.HierarchicalFirewall(
          policy.ParsePolicy(
              BAD_HEADER_INVALID_MAX_COST + TERM_ALLOW_ALL_INTERNAL,
              self.naming), EXP_INFO)

  def testRaisesHeaderErrorOnUnequalMaxCostInMultiplePolicies(self):
    """Test that unequal max costs across multiple policies raises a HeaderError."""
    with self.assertRaises(gcp.HeaderError):
      gcp_hf.HierarchicalFirewall(
          policy.ParsePolicy(
              HEADER_OPTION_MAX + TERM_ALLOW_ALL_INTERNAL +
              HEADER_OPTION_HIGH_QUOTA + TERM_ALLOW_ALL_INTERNAL, self.naming),
          EXP_INFO)

  def testRaisesHeaderErrorOnUnequalMaxCostInMultiplePoliciesWithDefault(self):
    """Test that unspecified, and set max costs across multiple policies raises a HeaderError."""
    with self.assertRaises(gcp.HeaderError):
      gcp_hf.HierarchicalFirewall(
          policy.ParsePolicy(
              HEADER_OPTION_MAX + TERM_ALLOW_ALL_INTERNAL +
              HEADER_NO_OPTIONS + TERM_ALLOW_ALL_INTERNAL, self.naming),
          EXP_INFO)

  def testRaisesHeaderErrorOnLongDisplayName(self):
    """Test that a long displayName raises a HeaderError."""
    with self.assertRaises(gcp.HeaderError):
      gcp_hf.HierarchicalFirewall(
          policy.ParsePolicy(BAD_HEADER_LONG_DISPLAYNAME
                             + TERM_ALLOW_ALL_INTERNAL,
                             self.naming),
          EXP_INFO)

  def testRaisesHeaderErrorOnHeaderWithoutDisplayName(self):
    """Test that a header without a policy name raises a HeaderError."""
    with self.assertRaises(gcp.HeaderError):
      gcp_hf.HierarchicalFirewall(
          policy.ParsePolicy(BAD_HEADER_NO_DISPLAYNAME
                             + TERM_ALLOW_ALL_INTERNAL, self.naming),
          EXP_INFO)

  def testRaisesHeaderErrorOnIncorrectDisplayName1(self):
    """Test that an invalid displayName raises a HeaderError."""
    with self.assertRaises(gcp.HeaderError):
      gcp_hf.HierarchicalFirewall(
          policy.ParsePolicy(BAD_HEADER_INVALID_DISPLAYNAME_1
                             + TERM_ALLOW_ALL_INTERNAL,
                             self.naming),
          EXP_INFO)

  def testRaisesHeaderErrorOnIncorrectDisplayName2(self):
    """Test that an invalid displayName raises a HeaderError."""
    with self.assertRaises(gcp.HeaderError):
      gcp_hf.HierarchicalFirewall(
          policy.ParsePolicy(BAD_HEADER_INVALID_DISPLAYNAME_2
                             + TERM_ALLOW_ALL_INTERNAL,
                             self.naming),
          EXP_INFO)

  def testRaisesHeaderErrorOnIncorrectDisplayName3(self):
    """Test that an invalid displayName raises a HeaderError."""
    with self.assertRaises(gcp.HeaderError):
      gcp_hf.HierarchicalFirewall(
          policy.ParsePolicy(BAD_HEADER_INVALID_DISPLAYNAME_3
                             + TERM_ALLOW_ALL_INTERNAL,
                             self.naming),
          EXP_INFO)

  def testRaisesTermErrorOnTermWithDestinationTag(self):
    """Test that a term with a destination tag raises an error.

    Tags are not supported in HF.
    """
    with self.assertRaises(gcp.TermError):
      gcp_hf.HierarchicalFirewall(
          policy.ParsePolicy(HEADER_NO_OPTIONS + BAD_TERM_USING_DEST_TAG,
                             self.naming),
          EXP_INFO)

  def testRaisesTermErrorOnTermWithSourceTag(self):
    """Test that a term with a source tag raises an error.

    Tags are not supported in HF.
    """
    with self.assertRaises(gcp.TermError):
      gcp_hf.HierarchicalFirewall(
          policy.ParsePolicy(HEADER_NO_OPTIONS + BAD_TERM_USING_SOURCE_TAG,
                             self.naming),
          EXP_INFO)

  def testTermWithNumberedProtocol(self):
    """Test that a protocol number is supported."""
    self.naming.GetNetAddr.return_value = ALL_IPV4_IPS

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_NO_OPTIONS + TERM_NUMBERED_PROTOCOL,
                           self.naming), EXP_INFO)
    expected = json.loads(EXPECTED_ONE_RULE_NUMBERED_PROTOCOL_BETA)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testRaisesTermErrorOnTermWithSourcePort(self):
    """Test that a term with a source port raises Term error."""
    self.naming.GetNetAddr.return_value = TEST_IP
    self.naming.GetServiceByProto.side_effect = [['53']]

    with self.assertRaises(gcp.TermError):
      gcp_hf.HierarchicalFirewall(
          policy.ParsePolicy(HEADER_NO_OPTIONS + BAD_TERM_SOURCE_PORT,
                             self.naming), EXP_INFO)

  def testRaisesTermErrorOnTermWithTooManyTargetResources(self):
    """Test that a term with > 256 targetResources raises TermError."""
    self.naming.GetNetAddr.return_value = TEST_IP

    with self.assertRaises(gcp.TermError):
      gcp_hf.HierarchicalFirewall(
          policy.ParsePolicy(HEADER_NO_OPTIONS + BAD_TERM_TARGET_RESOURCES,
                             self.naming), EXP_INFO)

  def testRaisesTermErrorOnTermWithTooManyDestinationPorts(self):
    """Test that a term with > 256 destination ports raises TermError."""
    self.naming.GetNetAddr.return_value = TEST_IP

    # Create a list of 260 numbers to use as destination ports and raise an
    # error.
    # Using even numbers ensures that the port list does not get condensed to a
    # range.
    se_array = []
    for x in range(2000, 2520):
      if x % 2 == 0:
        se_array.append([str(x)])
    # Use destination port list to successively mock return values.
    self.naming.GetServiceByProto.side_effect = se_array

    with self.assertRaises(gcp.TermError):
      gcp_hf.HierarchicalFirewall(
          policy.ParsePolicy(HEADER_NO_OPTIONS + BAD_TERM_DESTINATION_PORTS,
                             self.naming), EXP_INFO)

  def testRaisesTermErrorOnTermWithOptions(self):
    """Test that a term with a source port raises Term error."""
    self.naming.GetNetAddr.return_value = TEST_IP

    with self.assertRaises(gcp.TermError):
      gcp_hf.HierarchicalFirewall(
          policy.ParsePolicy(HEADER_NO_OPTIONS + BAD_TERM_OPTIONS,
                             self.naming),
          EXP_INFO)

  def testRaisesTermErrorOnInvalidProjectID(self):
    """Test that an invalid project ID on target resources raises Term error."""
    self.naming.GetNetAddr.return_value = TEST_IP

    with self.assertRaises(gcp.TermError):
      gcp_hf.HierarchicalFirewall(
          policy.ParsePolicy(HEADER_NO_OPTIONS + BAD_TERM_NON_VALID_PROJECT_ID,
                             self.naming),
          EXP_INFO)

  def testRaisesTermErrorOnInvalidVPCName(self):
    """Test that an invalid VPC name on target resources raises Term error."""
    self.naming.GetNetAddr.return_value = TEST_IP

    with self.assertRaises(gcp.TermError):
      gcp_hf.HierarchicalFirewall(
          policy.ParsePolicy(HEADER_NO_OPTIONS + BAD_TERM_NON_VALID_VPC_NAME,
                             self.naming),
          EXP_INFO)

  def testRaisesDifferentPolicyNameErrorWhenDifferentPolicyNames(self):
    """Test that different policy names raises DifferentPolicyNameError."""
    with self.assertRaises(gcp_hf.DifferentPolicyNameError):
      gcp_hf.HierarchicalFirewall(
          policy.ParsePolicy(HEADER_NO_OPTIONS + TERM_DENY_INGRESS
                             + HEADER_OPTION_EGRESS_2 + TERM_DENY_EGRESS,
                             self.naming),
          EXP_INFO)

  def testIgnorePolicyFromADifferentPlatform(self):
    """Test that a policy with a header from a different platform is ignored."""
    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(BAD_HEADER_WRONG_PLATFORM
                           + TERM_ALLOW_ALL_INTERNAL,
                           self.naming),
        EXP_INFO)
    self.assertEqual([], json.loads(self._StripAclHeaders(str(acl))))

  def testIgnoreTermWithPlatformExclude(self):
    """Test that a term with platform exclude is ignored."""
    self.naming.GetNetAddr.return_value = ALL_IPV4_IPS

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(
            HEADER_OPTION_AF + TERM_PLATFORM_EXCLUDE + TERM_ALLOW_ALL_INTERNAL,
            self.naming), EXP_INFO)
    expected = json.loads(EXPECTED_ONE_RULE_INGRESS_BETA)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testTermWithPlatformExists(self):
    """Test that a term with platform is rendered."""
    self.naming.GetNetAddr.return_value = ALL_IPV4_IPS

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(
            HEADER_OPTION_AF + TERM_PLATFORM_ALLOW_ALL_INTERNAL,
            self.naming), EXP_INFO)
    expected = json.loads(EXPECTED_ONE_RULE_INGRESS_BETA)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testIgnoreTermWithICMPv6(self):
    """Test that a term with only an icmpv6 protocol is not rendered."""
    self.naming.GetNetAddr.return_value = TEST_IP

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_OPTION_AF
                           + BAD_TERM_IP_VERSION_MISMATCH,
                           self.naming),
        EXP_INFO)
    exp = [{'displayName': 'displayname', 'rules': [], 'type': 'FIREWALL'}]
    self.assertEqual(exp, json.loads(self._StripAclHeaders(str(acl))))

  def testInet6IgnoreTermWithICMP(self):
    """Test that a term with only an icmp protocol is not rendered for inet6."""
    self.naming.GetNetAddr.return_value = TEST_IP

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_OPTION_INET6
                           + BAD_TERM_ICMP_VERSION_MISMATCH,
                           self.naming),
        EXP_INFO)
    exp = [{'shortName': 'displayname', 'rules': [], 'type': 'FIREWALL'}]
    self.assertEqual(exp, json.loads(self._StripAclHeaders(str(acl))))

  def testInet6IgnoreTermWithIGMP(self):
    """Test that a term with only an igmp protocol is not rendered for inet6."""
    self.naming.GetNetAddr.return_value = TEST_IP

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_OPTION_INET6
                           + BAD_TERM_IGMP_VERSION_MISMATCH,
                           self.naming),
        EXP_INFO)
    exp = [{'shortName': 'displayname', 'rules': [], 'type': 'FIREWALL'}]
    self.assertEqual(exp, json.loads(self._StripAclHeaders(str(acl))))

  def testInet6TermWithIPv6Addresses(self):
    """Test that IPv6 addresses are supported with inet6."""
    self.naming.GetNetAddr.return_value = TEST_IPV6_IP
    self.naming.GetServiceByProto.side_effect = [['80']]

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_OPTION_INET6 + TERM_ALLOW_PORT,
                           self.naming), EXP_INFO)
    expected = json.loads(EXPECTED_ONE_RULE_IPV6_PROTOCOL_GA)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testInet6TermWithMixedAddresses(self):
    """Test that Mixed addresses are supported with inet6."""
    self.naming.GetNetAddr.return_value = TEST_MIXED_IPS
    self.naming.GetServiceByProto.side_effect = [['80']]

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_OPTION_INET6 + TERM_ALLOW_PORT,
                           self.naming), EXP_INFO)
    expected = json.loads(EXPECTED_ONE_RULE_IPV6_PROTOCOL_GA)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testInet6TermWithIPv4Addresses(self):
    """Test that IPv4 addresses are not rendered with inet6."""
    self.naming.GetNetAddr.return_value = TEST_IP
    self.naming.GetServiceByProto.side_effect = [['80']]

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_OPTION_INET6 + TERM_ALLOW_PORT,
                           self.naming), EXP_INFO)
    exp = [{'shortName': 'displayname', 'rules': [], 'type': 'FIREWALL'}]
    self.assertEqual(exp, json.loads(self._StripAclHeaders(str(acl))))

  def testInetTermWithMixedAddresses(self):
    """Test that Mixed addresses are supported with inet."""
    self.naming.GetNetAddr.return_value = TEST_MIXED_IPS
    self.naming.GetServiceByProto.side_effect = [['80']]

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_OPTION_EGRESS_AND_AF + TERM_RESTRICT_EGRESS,
                           self.naming), EXP_INFO)
    expected = json.loads(EXPECTED_ONE_RULE_EGRESS_BETA)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testInetTermWithIPv6Addresses(self):
    """Test that IPv6 addresses are not rendered with inet."""
    self.naming.GetNetAddr.return_value = TEST_IPV6_IP
    self.naming.GetServiceByProto.side_effect = [['80']]

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_OPTION_EGRESS_AND_AF + TERM_RESTRICT_EGRESS,
                           self.naming), EXP_INFO)
    exp = [{'displayName': 'displayname', 'rules': [], 'type': 'FIREWALL'}]
    self.assertEqual(exp, json.loads(self._StripAclHeaders(str(acl))))

  def testMixedTermWithMixedAddresses(self):
    """Test that IPv4 and IPv6 addresses are supported with mixed."""
    self.naming.GetNetAddr.return_value = TEST_MIXED_IPS
    self.naming.GetServiceByProto.side_effect = [['80']]

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_OPTION_MIXED + TERM_ALLOW_PORT,
                           self.naming), EXP_INFO)
    expected = json.loads(EXPECTED_MULTIPLE_MIXED_RULE_INGRESS_GA)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testMixedTermWithIPv4Addresses(self):
    """Test that IPv4 addresses are supported with mixed."""
    self.naming.GetNetAddr.return_value = TEST_IP
    self.naming.GetServiceByProto.side_effect = [['80']]

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_OPTION_MIXED + TERM_ALLOW_PORT,
                           self.naming), EXP_INFO)
    expected = json.loads(EXPECTED_ONE_RULE_MIXED_IPV4_PROTOCOL_GA)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testMixedTermWithIPv6Addresses(self):
    """Test that IPv6 addresses are supported with mixed."""
    self.naming.GetNetAddr.return_value = TEST_IPV6_IP
    self.naming.GetServiceByProto.side_effect = [['80']]

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_OPTION_MIXED + TERM_ALLOW_PORT,
                           self.naming), EXP_INFO)
    expected = json.loads(EXPECTED_ONE_RULE_MIXED_IPV6_PROTOCOL_GA)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testMixedTermWithICMP(self):
    """Test that ICMP protocol is supported with mixed."""
    self.naming.GetNetAddr.return_value = TEST_MIXED_IPS
    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_OPTION_MIXED + TERM_ALLOW_MULTIPLE_PROTOCOL,
                           self.naming), EXP_INFO)
    expected = json.loads(EXPECTED_MULTIPLE_MIXED_RULE_INGRESS_WITH_ICMP_GA)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testMixedTermWithICMPv6(self):
    """Test that ICMPv6 protocol is supported with mixed."""
    self.naming.GetNetAddr.return_value = TEST_MIXED_IPS
    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(
            HEADER_OPTION_MIXED + TERM_ALLOW_MULTIPLE_PROTOCOL_ICMPV6,
            self.naming), EXP_INFO)
    expected = json.loads(EXPECTED_MULTIPLE_MIXED_RULE_INGRESS_WITH_ICMPV6_GA)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testInetIsDefaultInetVersion(self):
    """Test that inet is the default inet version when not specified."""
    self.naming.GetNetAddr.return_value = TEST_MIXED_IPS
    self.naming.GetServiceByProto.side_effect = [['80']]

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_GA_NO_INET_OPTIONS + TERM_ALLOW_PORT,
                           self.naming), EXP_INFO)
    expected = json.loads(EXPECTED_ONE_RULE_MIXED_IPV4_PROTOCOL_GA)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testPriority(self):
    """Test that priority is set based on terms' ordering."""
    self.naming.GetNetAddr.return_value = ALL_IPV4_IPS
    self.naming.GetServiceByProto.side_effect = [['53'], ['53']]

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_NO_OPTIONS + TERM_ALLOW_ALL_INTERNAL
                           + TERM_ALLOW_DNS, self.naming),
        EXP_INFO)
    expected = json.loads(EXPECTED_MULTIPLE_RULE_INGRESS_BETA)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testLogging(self):
    """Test that logging is used when it is set on a term."""
    self.naming.GetNetAddr.return_value = TEST_IP
    self.naming.GetServiceByProto.side_effect = [['53'], ['53']]

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_NO_OPTIONS + TERM_WITH_LOGGING, self.naming),
        EXP_INFO)
    expected = json.loads(EXPECTED_ONE_RULE_INGRESS_W_LOGGING_BETA)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testTargetResources(self):
    """Test that the target resources is used correctly."""
    self.naming.GetNetAddr.return_value = [nacaddr.IP('0.0.0.0/0')]

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_NO_OPTIONS + TERM_WITH_TARGET_RESOURCES,
                           self.naming),
        EXP_INFO)
    expected = json.loads(EXPECTED_DENY_INGRESS_ON_TARGET_BETA)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testSecondWayOfPassingTargetResources(self):
    """Test that the target resources is used correctly."""
    self.naming.GetNetAddr.return_value = [nacaddr.IP('0.0.0.0/0')]

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_NO_OPTIONS + TERM_WITH_TARGET_RESOURCES_2,
                           self.naming),
        EXP_INFO)
    expected = json.loads(EXPECTED_DENY_INGRESS_ON_TARGET_BETA)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testMultiplePolicies(self):
    """Tests that both ingress and egress rules are included in one policy."""
    self.maxDiff = None
    self.naming.GetNetAddr.return_value = ALL_IPV4_IPS

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_NO_OPTIONS + TERM_ALLOW_ALL_INTERNAL +
                           TERM_DENY_INGRESS + HEADER_OPTION_EGRESS +
                           TERM_RESTRICT_EGRESS + TERM_DENY_EGRESS,
                           self.naming),
        EXP_INFO)
    expected = json.loads(EXPECTED_INGRESS_AND_EGRESS_W_DENY_BETA)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testPortRange(self):
    """Test that a port range is accepted and used correctly."""
    self.naming.GetNetAddr.return_value = TEST_IP
    self.naming.GetServiceByProto.side_effect = [['8000-9000']]

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_NO_OPTIONS + TERM_ALLOW_PORT_RANGE,
                           self.naming),
        EXP_INFO)
    expected = json.loads(EXPECTED_PORT_RANGE_INGRESS_BETA)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testTermLongComment(self):
    """Test that a term's long comment gets truncated and prefixed with term name."""
    self.naming.GetNetAddr.return_value = ALL_IPV4_IPS

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_NO_OPTIONS + TERM_LONG_COMMENT,
                           self.naming),
        EXP_INFO)
    comment_truncated = EXPECTED_ONE_RULE_INGRESS_BETA.replace(
        'Generic description',
        'This is a very long description, it is l')
    expected = json.loads(comment_truncated)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testDefaultDenyIngressCreation(self):
    """Test that the correct IP is correctly set on a deny all ingress term."""
    self.naming.GetNetAddr.return_value = ALL_IPV4_IPS

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_NO_OPTIONS + TERM_DENY_INGRESS, self.naming),
        EXP_INFO)
    expected = json.loads(EXPECTED_DENY_INGRESS_BETA)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testInet6DefaultDenyIngressCreation(self):
    """Test that the IPv6 IP is correctly set on a deny all ingress term."""
    self.naming.GetNetAddr.return_value = ALL_IPV6_IPS

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_OPTION_INET6 + TERM_DENY_INGRESS,
                           self.naming), EXP_INFO)
    expected = json.loads(EXPECTED_IPV6_DENY_INGRESS_GA)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testMixedDefaultDenyIngressCreation(self):
    """Test that the mixed IPs are correctly set on a deny all ingress term."""

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_OPTION_MIXED + TERM_DENY_INGRESS,
                           self.naming), EXP_INFO)
    expected = json.loads(EXPECTED_MIXED_DENY_INGRESS_GA)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testDefaultDenyEgressCreation(self):
    """Test that the correct IP is correctly set on a deny all egress term."""
    self.naming.GetNetAddr.return_value = ALL_IPV4_IPS

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_OPTION_EGRESS + TERM_DENY_EGRESS,
                           self.naming),
        EXP_INFO)
    expected = json.loads(EXPECTED_DENY_EGRESS_BETA)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testInet6DefaultDenyEgressCreation(self):
    """Test that the IPv6 IP is correctly set on a deny all egress term."""
    self.naming.GetNetAddr.return_value = ALL_IPV6_IPS

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_OPTION_EGRESS_INET6 + TERM_DENY_EGRESS,
                           self.naming), EXP_INFO)
    expected = json.loads(EXPECTED_IPV6_DENY_EGRESS_GA)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testMixedDefaultDenyEgressCreation(self):
    """Test that the mixed IPs are correctly set on a deny all egress term."""

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_OPTION_EGRESS_MIXED + TERM_DENY_EGRESS,
                           self.naming), EXP_INFO)
    expected = json.loads(EXPECTED_MIXED_DENY_EGRESS_GA)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testBuildTokens(self):
    """Test that _BuildTokens generates the expected list of tokens."""
    self.naming.GetNetAddr.side_effect = [TEST_IP]

    pol1 = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_NO_OPTIONS + TERM_ALLOW_ALL_INTERNAL,
                           self.naming),
        EXP_INFO)
    st, sst = pol1._BuildTokens()
    self.assertEqual(st, SUPPORTED_TOKENS)
    self.assertEqual(sst, SUPPORTED_SUB_TOKENS)

  def testRaisesExceededCostError(self):
    """Test that ExceededCostError is raised when policy exceeds max cost."""
    self.naming.GetNetAddr.side_effect = [TEST_IP]
    with self.assertRaises(gcp_hf.ExceededCostError):
      gcp_hf.HierarchicalFirewall(
          policy.ParsePolicy(HEADER_VERY_LOW_DEFAULT_MAX
                             + TERM_ALLOW_ALL_INTERNAL, self.naming),
          EXP_INFO)

  def testChunkedIPRanges(self):
    """Test that source IP ranges that exceed limit are chunked."""
    self.maxDiff = None
    self.naming.GetNetAddr.side_effect = [MANY_IPS]
    self.naming.GetServiceByProto.side_effect = [['80']]
    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_OPTION_HIGH_QUOTA + TERM_ALLOW_PORT,
                           self.naming),
        EXP_INFO)
    expected = json.loads(EXPECTED_CHUNKED_BETA)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testChunkedEgressIPRanges(self):
    """Test that destination IP ranges that exceed limit are chunked."""
    self.maxDiff = None
    self.naming.GetNetAddr.side_effect = [MANY_IPS]
    self.naming.GetServiceByProto.side_effect = [['80']]
    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_OPTION_EGRESS_HIGH_QUOTA +
                           TERM_ALLOW_EGRESS_PORT, self.naming),
        EXP_INFO)
    expected = json.loads(EXPECTED_EGRESS_CHUNKED_BETA)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  @parameterized.named_parameters(
      ('1 ip, 2 protocols',
       {'match': {
           'config': {
               'destIpRanges': ['0.0.0.0/0'],
               'layer4Configs': [
                   {'ipProtocol': 'tcp'},
                   {'ipProtocol': 'icmp'}
               ]
           }
       }}, 3),
      ('1 ip, 3 protocols, ',
       {'match': {
           'config': {
               'srcIpRanges': ['0.0.0.0/0'],
               'layer4Configs': [
                   {'ipProtocol': 'tcp'},
                   {'ipProtocol': 'icmp'},
                   {'ipProtocol': 'udp'}
               ]
           }
       }}, 4),
      ('1 ip, 1 protocol with 1 port',
       {'match': {
           'config': {
               'srcIpRanges': ['0.0.0.0/0'],
               'layer4Configs': [
                   {'ipProtocol': 'tcp', 'ports': ['22']}
               ]
           }
       }}, 3),
      ('1 ip, 2 protocols with 2 ports each',
       {'match': {
           'config': {
               'srcIpRanges': ['0.0.0.0/0'],
               'layer4Configs': [
                   {'ipProtocol': 'tcp', 'ports': ['22']},
                   {'ipProtocol': 'udp', 'ports': ['22']}
               ]
           }
       }}, 5),
      ('1 ip, 1 protocol with 2 ports',
       {'match': {
           'config': {
               'srcIpRanges': ['0.0.0.0/0'],
               'layer4Configs': [
                   {'ipProtocol': 'tcp', 'ports': ['22', '23']}
               ]
           }
       }}, 4),
      ('2 ips, 1 protocol with 2 ports',
       {'match': {
           'config': {
               'srcIpRanges': ['1.4.6.8/10', '1.2.3.4/5'],
               'layer4Configs': [
                   {'ipProtocol': 'tcp', 'ports': ['22', '23']}
               ]
           }
       }}, 5),
      ('2 ips, 2 protocols with 2 ports each',
       {'match': {
           'config': {
               'srcIpRanges': ['1.4.6.8/10', '1.2.3.4/5'],
               'layer4Configs': [
                   {'ipProtocol': 'tcp', 'ports': ['22', '23']},
                   {'ipProtocol': 'udp', 'ports': ['22', '23']}
               ]
           }
       }}, 8),
      ('1 ip, 2 protocols, 2 targets',
       {'match': {
           'config': {
               'destIpRanges': ['0.0.0.0/0'],
               'layer4Configs': [
                   {'ipProtocol': 'tcp'},
                   {'ipProtocol': 'icmp'}
               ]
           }
       },
        'targetResources': ['target1', 'target2']
       }, 5),
  )
  def testGetRuleTupleCount(self, dict_term, expected):
    self.assertEqual(gcp_hf.GetRuleTupleCount(dict_term, 'beta'), expected)

  @parameterized.named_parameters(
      ('1 ip, 2 protocols', {
          'match': {
              'destIpRanges': ['0.0.0.0/0'],
              'layer4Configs': [{
                  'ipProtocol': 'tcp'
              }, {
                  'ipProtocol': 'icmp'
              }]
          }
      }, 3),
      ('1 ip, 3 protocols, ', {
          'match': {
              'srcIpRanges': ['0.0.0.0/0'],
              'layer4Configs': [{
                  'ipProtocol': 'tcp'
              }, {
                  'ipProtocol': 'icmp'
              }, {
                  'ipProtocol': 'udp'
              }]
          }
      }, 4),
      ('1 ip, 1 protocol with 1 port', {
          'match': {
              'srcIpRanges': ['0.0.0.0/0'],
              'layer4Configs': [{
                  'ipProtocol': 'tcp',
                  'ports': ['22']
              }]
          }
      }, 3),
      ('1 ip, 2 protocols with 2 ports each', {
          'match': {
              'srcIpRanges': ['0.0.0.0/0'],
              'layer4Configs': [{
                  'ipProtocol': 'tcp',
                  'ports': ['22']
              }, {
                  'ipProtocol': 'udp',
                  'ports': ['22']
              }]
          }
      }, 5),
      ('1 ip, 1 protocol with 2 ports', {
          'match': {
              'srcIpRanges': ['0.0.0.0/0'],
              'layer4Configs': [{
                  'ipProtocol': 'tcp',
                  'ports': ['22', '23']
              }]
          }
      }, 4),
      ('2 ips, 1 protocol with 2 ports', {
          'match': {
              'srcIpRanges': ['1.4.6.8/10', '1.2.3.4/5'],
              'layer4Configs': [{
                  'ipProtocol': 'tcp',
                  'ports': ['22', '23']
              }]
          }
      }, 5),
      ('2 ips, 2 protocols with 2 ports each', {
          'match': {
              'srcIpRanges': ['1.4.6.8/10', '1.2.3.4/5'],
              'layer4Configs': [{
                  'ipProtocol': 'tcp',
                  'ports': ['22', '23']
              }, {
                  'ipProtocol': 'udp',
                  'ports': ['22', '23']
              }]
          }
      }, 8),
      ('1 ip, 2 protocols, 2 targets', {
          'match': {
              'destIpRanges': ['0.0.0.0/0'],
              'layer4Configs': [{
                  'ipProtocol': 'tcp'
              }, {
                  'ipProtocol': 'icmp'
              }]
          },
          'targetResources': ['target1', 'target2']
      }, 5),
  )
  def testGAGetRuleTupleCount(self, dict_term, expected):
    self.assertEqual(gcp_hf.GetRuleTupleCount(dict_term, 'ga'), expected)


if __name__ == '__main__':
  absltest.main()

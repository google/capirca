import random
import ipaddress
import itertools as it


def write_excludes_testcase(ipstr, excludelist='', max_prefix_range=8, max_random_subnets=30):
    """
    Writes a testcase to the tests/utils/address_exclude_test_cases.txt file.
    Note that the number of prefixes to consider grows exponentially, so unless
    you *do* want to consider a large pool to randomly select from, keep it at the default

    Args:
      ipstr: the ip network as a string (v4 or v6) to base the test on.
      excludelist: optional comma-separated string of ip networks to exclude
      max_prefix_range: the largest number of prefixes to consider.
      max_random_subnets: the number of subnets to do exclusion tests for, if randomly generating
    Returns:
      None
    """
    ip = ipaddress.ip_network(ipstr)
    if len(excludelist) == 0:  # empty excludelist, making a random one
        prefixrange = min(max_prefix_range, ip.max_prefixlen - ip.prefixlen)
        excludelist = it.chain.from_iterable(ip.subnets(i) for i in range(1, prefixrange+1))
        total_ips = 2**prefixrange
        ip_positions = set(
            random.choices(
                range(total_ips),
                k=min(
                    max_random_subnets,
                    total_ips
                )
            )
        )
        compress_map = (1 if i in ip_positions else 0 for i in range(total_ips))
        excludelist = list(it.compress(excludelist, compress_map))
    else:
        excludelist = list(map(ipaddress.ip_network, excludelist.split(',')))

    result_list = []
    for address in excludelist:
        result_list.append(ip.address_exclude(address))

    ipst = str(ip)
    exst = ",".join(map(str, excludelist))
    rest = ";".join(",".join(map(str, sorted(result))) for result in result_list)
    with open('tests/utils/address_exclude_test_cases.txt', 'a') as f:
        f.write("%s %s %s\n" % (ipst, exst, rest))

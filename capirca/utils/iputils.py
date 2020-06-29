from ipaddress import summarize_address_range, _BaseNetwork


def exclude_address(base_net: _BaseNetwork, exclude_net: _BaseNetwork):
  '''
  Function to exclude a subnetwork from another, returning a generator that yields
  all values that correspond to the base network without the exclude network.

  This is functionally equivalent to the _BaseNetwork "address_exclude" from the
  `ipaddress` standard library, but is a faster implementation since
  the standard library function is a O(n) operation on the length of the
  netmask of the excluding network, whereas this function is O(1) for all cases.

  args:
    base_net: an object of type _BaseNetwork, the network that
              contains the exclude network
    exclude_net: an object of type _BaseNetwork, the network
                 that is being removed from the base_net
  raises:
    ValueError if exclude_net is not completely contained in base_net
  '''

  if not base_net._version == exclude_net._version:
    raise TypeError("%s and %s are not of the same version" % (
      base_net, exclude_net))

  if not isinstance(exclude_net, _BaseNetwork):
    raise TypeError("%s is not a network object" % exclude_net)

  if not exclude_net.subnet_of(base_net):
    raise ValueError()
  if exclude_net == base_net:
    return

  include_range = base_net.network_address._ip, base_net.broadcast_address._ip
  exclude_range = exclude_net.network_address._ip, exclude_net.broadcast_address._ip
  address_class = base_net.network_address.__class__
  if include_range[0] == exclude_range[0]:
    result_start = address_class(exclude_range[1]+1)
    result_end = address_class(include_range[1])
    yield from summarize_address_range(result_start, result_end)
  elif include_range[1] == exclude_range[1]:
    result_start = address_class(include_range[0])
    result_end = address_class(exclude_range[0]-1)
    yield from summarize_address_range(result_start, result_end)
  else:
    first_section_start = address_class(include_range[0])
    first_section_end = address_class(exclude_range[0]-1)
    second_section_start = address_class(exclude_range[1]+1)
    second_section_end = address_class(include_range[1])
    yield from summarize_address_range(first_section_start, first_section_end)
    yield from summarize_address_range(second_section_start, second_section_end)

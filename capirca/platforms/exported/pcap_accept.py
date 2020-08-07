from capirca.platforms import pcap

class PcapAcceptFilter(pcap.PcapFilter):
    SUFFIX = "-accept.pcap"

PLATFORM = "pcap_accept"
RENDERER = PcapAcceptFilter

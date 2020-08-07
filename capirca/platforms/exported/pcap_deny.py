from capirca.platforms import pcap

class PcapDenyFilter(pcap.PcapFilter):
    SUFFIX = "-deny.pcap"

    def __init__(*args, **kwargs):
        super(PcapDenyFilter, self).__init__(*args, invert=True, **kwargs)

PLATFORM = "pcap_deny"
RENDERER = PcapDenyFilter

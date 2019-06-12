firewall {
    family inet {
        replace:
        /*
        ** $Id:$
        ** $Date:$
        ** $Revision:$
        **
        */
        filter edge-filter {
            interface-specific;
            term allow-https-web {
                from {
                    destination-address {
                        /* Example web server 1 */
                        200.1.1.1/32;
                        /* Example web server 2 */
                        200.1.1.2/32;
                    }
                    protocol tcp;
                    destination-port [ 80 443 ];
                }
                then accept;
            }
            term customers-policy {
                from {
                    source-address {
                        4.71.113.2/32;
                    }
                    destination-address {
                        4.71.113.2/32;
                    }
                    protocol tcp;
                    destination-port [ 80 443 ];
                }
                then {
                    discard;
                }
            }
            term good-term-2 {
                from {
                    destination-address {
                        9.9.9.9/32;
                    }
                    protocol tcp;
                    source-port 993;
                }
                then accept;
            }
            term customers-policy2 {
                from {
                    source-address {
                        9.9.9.9/32;
                    }
                    destination-address {
                        192.168.1.0/24;
                    }
                    protocol tcp;
                    destination-port [ 80 443 ];
                }
                then {
                    syslog;
                    discard;
                }
            }
            term deny-any-any {
                from {
                    protocol icmp;
                }
                then {
                    discard;
                }
            }
            term accept-any-any {
                from {
                    protocol udp;
                    destination-port 43;
                }
                then accept;
            }
        }
    }
}

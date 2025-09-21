open module com.github.hirsivaja.jipcs {
    requires java.base;
    requires java.logging;

    exports com.github.hirsivaja.ip;
    exports com.github.hirsivaja.ip.ethernet;
    exports com.github.hirsivaja.ip.icmp;
    exports com.github.hirsivaja.ip.icmpv6;
    exports com.github.hirsivaja.ip.icmpv6.mld;
    exports com.github.hirsivaja.ip.icmpv6.mpl;
    exports com.github.hirsivaja.ip.icmpv6.mrd;
    exports com.github.hirsivaja.ip.icmpv6.ndp;
    exports com.github.hirsivaja.ip.icmpv6.ndp.option;
    exports com.github.hirsivaja.ip.icmpv6.rpl;
    exports com.github.hirsivaja.ip.icmpv6.rpl.base;
    exports com.github.hirsivaja.ip.icmpv6.rpl.option;
    exports com.github.hirsivaja.ip.icmpv6.rpl.security;
    exports com.github.hirsivaja.ip.icmpv6.rr;
    exports com.github.hirsivaja.ip.igmp;
    exports com.github.hirsivaja.ip.ipsec;
    exports com.github.hirsivaja.ip.ipv4;
    exports com.github.hirsivaja.ip.ipv6;
    exports com.github.hirsivaja.ip.ipv6.extension;
    exports com.github.hirsivaja.ip.ipv6.extension.destination;
    exports com.github.hirsivaja.ip.ipv6.extension.mobility;
    exports com.github.hirsivaja.ip.tcp;
    exports com.github.hirsivaja.ip.udp;
}

package com.github.hirsivaja.ip.integration;

import com.github.hirsivaja.ip.EcnCodePoint;
import com.github.hirsivaja.ip.ethernet.EthernetPayload;
import com.github.hirsivaja.ip.icmp.IcmpCodes;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Codes;
import com.github.hirsivaja.ip.igmp.IgmpType;
import com.github.hirsivaja.ip.ipv4.Ipv4Address;
import com.github.hirsivaja.ip.ipv6.Ipv6Address;
import com.github.hirsivaja.ip.tcp.TcpHeader;
import com.github.hirsivaja.ip.udp.UdpHeader;
import org.junit.Assert;
import org.junit.Test;

public class ModuleTest {

    @Test
    public void accessTest() {
        Assert.assertNotNull(EcnCodePoint.ECN_0_ECT_0);
        Assert.assertNotNull(EthernetPayload.ARP);
        Assert.assertNotNull(IcmpCodes.BAD_LENGTH);
        Assert.assertNotNull(Icmpv6Codes.REDIRECT_MESSAGE);
        Assert.assertNotNull(IgmpType.CONFIRM_GROUP_REPLY);
        Assert.assertNotNull(Ipv4Address.IPV4_ADDRESS_LEN);
        Assert.assertNotNull(Ipv6Address.IPV6_ADDRESS_LEN);
        Assert.assertNotNull(TcpHeader.TCP_HEADER_LEN);
        Assert.assertNotNull(UdpHeader.UDP_HEADER_LEN);
    }
}

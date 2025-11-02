package com.github.hirsivaja.ip.packet.payload

import com.github.hirsivaja.ip.packet.IpPacket
import com.github.hirsivaja.ip.packet.payload.udp.UdpDatagram
import com.github.hirsivaja.ip.packet.payload.udp.UdpHeader
import kotlin.test.Test

class UdpDatagramTest {

    @Test
    fun ipv4UdpDatagramTest() {
        val packetString = "45C0003E000000000111CEEB0A000002E000000202860286002A60E10001001E0AC8C8660000010000140000000004000004000F0000040100040AC8C866"
        val packet: IpPacket = IpPacket.fromByteString(packetString)
        val encodedString = packet.toByteString()

        val udpDatagram = packet.payload as UdpDatagram
        val udpHeader: UdpHeader = udpDatagram.udpHeader
        assert(646.toUShort() == udpHeader.srcPort)
        assert(646.toUShort() == udpHeader.dstPort)
        assert(34 == udpDatagram.data.length())
        assert(packetString == encodedString)
    }

    @Test
    fun ipv6UdpDatagramTest() {
        val packetString = "600000000042113E200300DE201601FF0000000000000011200300DE20160125FC3683174E86CB7200A1FF5000420FF6303802010104146E35724144316967333134497166696F59425777A21D020455E8832A020100020100300F300D06082B060102010B0500410100"
        val packet: IpPacket = IpPacket.fromByteString(packetString)
        val encodedString = packet.toByteString()

        val udpDatagram = packet.payload as UdpDatagram
        val udpHeader: UdpHeader = udpDatagram.udpHeader
        assert(161.toUShort() == udpHeader.srcPort)
        assert(65360.toUShort() == udpHeader.dstPort)
        assert(58 == udpDatagram.data.length())
        assert(packetString == encodedString)
    }
}

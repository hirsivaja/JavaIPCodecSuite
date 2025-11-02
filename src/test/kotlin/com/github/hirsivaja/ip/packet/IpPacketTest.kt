package com.github.hirsivaja.ip.packet

import com.github.hirsivaja.ip.packet.payload.Ipv4Payload
import com.github.hirsivaja.ip.packet.payload.Ipv6Payload
import kotlin.test.Test

class IpPacketTest {

    @Test
    fun genericIpv4Test() {
        val genericString = "450200180000E000007BDA690000000000000000000000000000000000000000000000000000000000000000"
        val genericBytes: ByteArray = genericString.hexToByteArray()
        val packet: IpPacket = IpPacket.fromBytes(genericBytes)
        val encodedString = packet.toByteString()

        assert(packet is Ipv4Packet)
        assert(packet.payload is Ipv4Payload.Generic)
        assert(genericString == encodedString)
    }

    @Test
    fun genericIpv6Test() {
        val genericString = "6000000000187B001234545236234523451123421433453275242334234234234412341232342342000000000000000000000000000000000000000000000000"
        val packet: IpPacket = IpPacket.fromByteString(genericString)
        val encodedString = packet.toByteString()

        assert(packet is Ipv6Packet)
        assert(packet.payload is Ipv6Payload.Generic)
        assert(genericString == encodedString)
    }
}

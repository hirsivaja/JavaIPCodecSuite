package com.github.hirsivaja.ip

import com.github.hirsivaja.ip.payload.Generic
import org.scalatest.flatspec.AnyFlatSpec

import java.util.HexFormat

class IpPacketSpec extends AnyFlatSpec {
  it should "create a generic IPv4 packet" in {
    val genericString = "450200180000E000007BDA690000000000000000000000000000000000000000000000000000000000000000"
    val genericBytes = HexFormat.of.parseHex(genericString)
    val packet: IpPacket = IpPacket.fromBytes(genericBytes)
    val encodedString = packet.toByteString

    assert(packet.isInstanceOf[Ipv4Packet])
    assert(packet.payload.isInstanceOf[Generic])
    assert(genericString == encodedString)
  }

  it should "create a generic IPv6 packet" in {
    val genericString = "6000000000187B001234545236234523451123421433453275242334234234234412341232342342000000000000000000000000000000000000000000000000"
    val packet: IpPacket = IpPacket.fromByteString(genericString)
    val encodedString = HexFormat.of.formatHex(packet.toBytes).toUpperCase

    assert(packet.isInstanceOf[Ipv6Packet])
    assert(packet.payload.isInstanceOf[Generic])
    assert(genericString == encodedString)
  }
}

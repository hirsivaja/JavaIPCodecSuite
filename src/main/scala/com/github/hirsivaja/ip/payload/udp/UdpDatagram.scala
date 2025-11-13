package com.github.hirsivaja.ip.payload.udp

import com.github.hirsivaja.ip.IpUtils
import com.github.hirsivaja.ip.header.IpHeader
import com.github.hirsivaja.ip.payload.{Ipv4Payload, Ipv6Payload}

import java.nio.ByteBuffer

case class UdpDatagram(udpHeader: UdpHeader, data: Array[Byte]) extends Ipv4Payload with Ipv6Payload {

  val length: Int = udpHeader.length + data.length

  def encode(out: ByteBuffer): Unit = {
    udpHeader.encode(out)
    out.put(data)
  }
}

object UdpDatagram {
  private def generateChecksumData(header: IpHeader, datagram: UdpDatagram) = {
    val checksumBuf = ByteBuffer.allocate(header.pseudoHeaderLength + datagram.length)
    checksumBuf.put(header.generatePseudoHeader())
    datagram.udpHeader.encode(checksumBuf)
    checksumBuf.put(datagram.data)
    val checksumData = new Array[Byte](checksumBuf.rewind.remaining)
    checksumBuf.get(checksumData)
    checksumData
  }

  def decode(in: ByteBuffer, ensureChecksum: Boolean, ipHeader: IpHeader): UdpDatagram = {
    val udpHeader = UdpHeader.decode(in)
    val data = new Array[Byte]((udpHeader.len & 0xFFFF) - UdpHeader.UdpHeaderLen)
    in.get(data)
    val datagram = new UdpDatagram(udpHeader, data)
    if (ensureChecksum) IpUtils.ensureInternetChecksum(generateChecksumData(ipHeader, datagram))
    else IpUtils.verifyInternetChecksum(generateChecksumData(ipHeader, datagram))
    datagram
  }
}

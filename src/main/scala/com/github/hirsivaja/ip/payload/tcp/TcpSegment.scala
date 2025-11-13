package com.github.hirsivaja.ip.payload.tcp

import com.github.hirsivaja.ip.IpUtils
import com.github.hirsivaja.ip.header.IpHeader
import com.github.hirsivaja.ip.payload.{Ipv4Payload, Ipv6Payload}

import java.nio.ByteBuffer

case class TcpSegment(tcpHeader: TcpHeader, data: Array[Byte]) extends Ipv4Payload with Ipv6Payload {
  val length: Int = tcpHeader.length + data.length

  def encode(out: ByteBuffer): Unit = {
    tcpHeader.encode(out)
    out.put(data)
  }
}

object TcpSegment {
  private def generateChecksumData(header: IpHeader, segment: TcpSegment) = {
    val checksumBuf = ByteBuffer.allocate(header.pseudoHeaderLength + segment.length)
    checksumBuf.put(header.generatePseudoHeader())
    segment.tcpHeader.encode(checksumBuf)
    checksumBuf.put(segment.data)
    val checksumData = new Array[Byte](checksumBuf.rewind.remaining)
    checksumBuf.get(checksumData)
    checksumData
  }

  def decode(in: ByteBuffer, ensureChecksum: Boolean, ipHeader: IpHeader): TcpSegment = {
    val tcpHeader = TcpHeader.decode(in)
    val data = new Array[Byte](in.remaining)
    in.get(data)
    val segment = new TcpSegment(tcpHeader, data)
    if (ensureChecksum) {
      IpUtils.ensureInternetChecksum(generateChecksumData(ipHeader, segment))
    } else {
      IpUtils.verifyInternetChecksum(generateChecksumData(ipHeader, segment))
    }
    segment
  }
}

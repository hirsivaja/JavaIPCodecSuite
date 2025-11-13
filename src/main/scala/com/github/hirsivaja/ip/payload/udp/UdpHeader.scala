package com.github.hirsivaja.ip.payload.udp

import java.nio.ByteBuffer

case class UdpHeader(srcPort: Short, dstPort: Short, len: Short, checksum: Short) {
  def this(srcPort: Short, dstPort: Short, len: Short) = {
    this(srcPort, dstPort, len, 0.toShort)
  }

  val length: Int = UdpHeader.UdpHeaderLen

  def encode(out: ByteBuffer): Unit = {
    out.putShort(srcPort)
    out.putShort(dstPort)
    out.putShort(len)
    out.putShort(checksum)
  }
}

object UdpHeader {
  val UdpHeaderLen: Int = 8

  def decode(in: ByteBuffer): UdpHeader = {
    val srcPort = in.getShort
    val dstPort = in.getShort
    val len = in.getShort
    val checksum = in.getShort
    new UdpHeader(srcPort, dstPort, len, checksum)
  }
}

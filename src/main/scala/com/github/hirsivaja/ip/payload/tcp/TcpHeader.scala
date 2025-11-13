package com.github.hirsivaja.ip.payload.tcp

import java.nio.ByteBuffer

case class TcpHeader(srcPort: Short,
                     dstPort: Short,
                     sequenceNumber: Int,
                     ackNumber: Int,
                     flags: Byte,
                     windowSize: Short,
                     checksum: Short,
                     urgentPointer: Short,
                     options: Array[Byte]) {
  val length: Int = TcpHeader.TcpHeaderLen + options.length

  def encode(out: ByteBuffer): Unit = {
    out.putShort(srcPort)
    out.putShort(dstPort)
    out.putInt(sequenceNumber)
    out.putInt(ackNumber)
    out.put((((options.length / 4) + 5) << TcpHeader.DataOffsetShift).toByte)
    out.put(flags)
    out.putShort(windowSize)
    out.putShort(checksum)
    out.putShort(urgentPointer)
    out.put(options)
  }
}

object TcpHeader {
  private val TcpHeaderLen: Int = 20
  private val DataOffsetShift: Int = 4

  def decode(in: ByteBuffer): TcpHeader = {
    val srcPort: Short = in.getShort
    val dstPort: Short = in.getShort
    val sequenceNumber: Int = in.getInt
    val ackNumber: Int = in.getInt
    val dataOffset: Int = (in.get >>> DataOffsetShift) & 0x0F
    val flags: Byte = in.get
    val windowSize: Short = in.getShort
    val checksum: Short = in.getShort
    val urgentPointer: Short = in.getShort
    val options: Array[Byte] = new Array[Byte]((dataOffset - 5) * 4)
    in.get(options)
    new TcpHeader(srcPort, dstPort, sequenceNumber, ackNumber, flags, windowSize, checksum, urgentPointer, options)
  }
}

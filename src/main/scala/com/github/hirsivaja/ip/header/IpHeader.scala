package com.github.hirsivaja.ip.header

import com.github.hirsivaja.ip.address.{Ipv4Address, Ipv6Address}
import com.github.hirsivaja.ip.{IpProtocol, IpUtils}

import java.nio.ByteBuffer

sealed trait IpHeader {
  val length: Int
  val protocol: IpProtocol
  val pseudoHeaderLength: Int

  def encode(out: ByteBuffer): Unit

  def generatePseudoHeader(): Array[Byte]
}

final case class Ipv4Header(ihl: Byte,
                            ecn: Byte,
                            dscp: Byte,
                            len: Short,
                            identification: Short,
                            flags: Byte,
                            fragmentOffset: Short,
                            ttl: Byte,
                            protocol: IpProtocol,
                            srcIp: Ipv4Address,
                            dstIp: Ipv4Address,
                            options: Array[Byte]) extends IpHeader {
  override val length: Int = Ipv4Header.HeaderLen + options.length
  override val pseudoHeaderLength: Int = Ipv4Header.PseudoHeaderLen

  override def encode(out: ByteBuffer): Unit = {
    out.mark
    val versionIhl = (Ipv4Header.Version << Ipv4Header.VersionShift | ((options.length / 4) + 5)).toByte
    out.put(versionIhl)
    val dscpEcn = (ecn & 0xFF | (dscp << Ipv4Header.DscpShift)).toByte
    out.put(dscpEcn)
    out.putShort(len)
    out.putShort(identification)
    val flagsFragmentOffset = (fragmentOffset | (flags << Ipv4Header.FlagsShift)).toShort
    out.putShort(flagsFragmentOffset)
    out.put(ttl)
    out.put(protocol.protocol)
    val checksumPosition = out.position
    out.putShort(0.toShort)
    srcIp.encode(out)
    dstIp.encode(out)
    out.put(options)
    val position = out.position
    val headerBytes = new Array[Byte](Ipv4Header.HeaderLen + options.length)
    out.reset.get(headerBytes)
    val checksum = IpUtils.calculateInternetChecksum(headerBytes)
    out.putShort(checksumPosition, checksum)
    out.position(position)
  }

  override def generatePseudoHeader(): Array[Byte] = {
    val out = ByteBuffer.allocate(Ipv4Header.PseudoHeaderLen)
    srcIp.encode(out)
    dstIp.encode(out)
    out.put(0.toByte)
    out.put(protocol.protocol)
    out.putShort((len - Ipv4Header.HeaderLen - options.length).toShort)
    val outBytes = new Array[Byte](Ipv4Header.PseudoHeaderLen)
    out.rewind.get(outBytes)
    outBytes
  }
}

object Ipv4Header {
  val Version: Int = 4
  val VersionShift: Int = 4
  private val HeaderLen: Int = 20
  private val PseudoHeaderLen: Int = 12
  private val DscpShift: Int = 2
  private val FlagsShift: Int = 13

  def decode(in: ByteBuffer, ensureChecksum: Boolean): Ipv4Header = {
    in.mark
    var version = in.get
    val ihl = (version & 0x0F).toByte
    version = (version >>> VersionShift).toByte
    if (version != Version) throw new IllegalArgumentException("Unexpected version for IPv4 header! " + version)
    var dscp = in.get
    val ecn = (dscp & 0x03).toByte
    dscp = (dscp >>> DscpShift).toByte
    val len = in.getShort
    val identification = in.getShort
    var fragmentOffset = in.getShort
    val flags = (fragmentOffset >>> FlagsShift).toByte
    fragmentOffset = (fragmentOffset & 0x1FFF).toShort
    val ttl = in.get
    val protocol = IpProtocol.fromType(in.get)
    in.getShort // Checksum
    val srcIp = Ipv4Address.decode(in)
    val dstIp = Ipv4Address.decode(in)
    val options = new Array[Byte]((ihl - 5) * 4)
    in.get(options)

    in.reset
    val headerBytes = new Array[Byte](HeaderLen + (ihl - 5) * 4)
    in.get(headerBytes)

    if (ensureChecksum) {
      IpUtils.ensureInternetChecksum(headerBytes)
    } else {
      IpUtils.verifyInternetChecksum(headerBytes)
    }
    new Ipv4Header(ihl, ecn, dscp, len, identification, flags, fragmentOffset, ttl, protocol, srcIp, dstIp, options)
  }
}

final case class Ipv6Header(ecn: Byte,
                            dscp: Byte,
                            flowLabel: Int,
                            payloadLength: Short,
                            nextHeader: IpProtocol,
                            hopLimit: Byte,
                            sourceAddress: Ipv6Address,
                            destinationAddress: Ipv6Address) extends IpHeader {

  override val length: Int = Ipv6Header.HeaderLen
  override val protocol: IpProtocol = nextHeader
  override val pseudoHeaderLength: Int = Ipv6Header.HeaderLen

  override def encode(out: ByteBuffer): Unit = {
    val trafficClass = (ecn & 0xFF | (dscp << Ipv6Header.DscpShift)).toByte
    var start = 0
    start |= (Ipv6Header.Version << Ipv6Header.VersionShift)
    start |= (trafficClass << Ipv6Header.TrafficClassShift) & Ipv6Header.TrafficClassMask
    start |= flowLabel & Ipv6Header.FlowLabelMask
    out.putInt(start)
    out.putShort(payloadLength)
    out.put(nextHeader.protocol)
    out.put(hopLimit)
    sourceAddress.encode(out)
    destinationAddress.encode(out)
  }

  override def generatePseudoHeader(): Array[Byte] = {
    val out = ByteBuffer.allocate(Ipv6Header.HeaderLen)
    sourceAddress.encode(out)
    destinationAddress.encode(out)
    out.putInt(payloadLength & 0xFFFF)
    out.put(0.toByte)
    out.put(0.toByte)
    out.put(0.toByte)
    out.put(nextHeader.protocol)
    val outBytes = new Array[Byte](Ipv6Header.HeaderLen)
    out.rewind.get(outBytes)
    outBytes
  }
}

object Ipv6Header {
  val Version: Int = 6
  private val HeaderLen: Int = 40
  private val VersionShift: Int = 28
  private val TrafficClassMask: Int = 0xFF00000
  private val TrafficClassShift: Int = 20
  private val DscpShift: Int = 2
  private val FlowLabelMask: Int = 0xFFFFF

  def decode(in: ByteBuffer): Ipv6Header = {
    val start: Int = in.getInt
    val version: Byte = (start >>> VersionShift).toByte
    if (version != Version) throw new IllegalArgumentException("Unexpected version for IPv6 header! " + version)
    var dscp: Byte = ((start & TrafficClassMask) >>> TrafficClassShift).toByte
    val ecn: Byte = (dscp & 0x03).toByte
    dscp = (dscp >>> DscpShift).toByte
    val flowLabel: Int = start & FlowLabelMask
    val payloadLength: Short = in.getShort
    val nextHeader: IpProtocol = IpProtocol.fromType(in.get)
    val hopLimit: Byte = in.get
    val sourceAddress: Ipv6Address = Ipv6Address.decode(in)
    val destinationAddress: Ipv6Address = Ipv6Address.decode(in)
    new Ipv6Header(dscp, ecn, flowLabel, payloadLength, nextHeader, hopLimit, sourceAddress, destinationAddress)
  }
}

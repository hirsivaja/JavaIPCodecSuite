package com.github.hirsivaja.ip

import com.github.hirsivaja.ip.header.{IpHeader, Ipv4Header, Ipv6Header}
import com.github.hirsivaja.ip.payload.{IpPayload, Ipv4Payload, Ipv6Payload}

import java.nio.ByteBuffer
import java.util.HexFormat

sealed trait IpPacket {
  val header: IpHeader
  val payload: IpPayload
  val length: Int = header.length + payload.length

  def encode(out: ByteBuffer): Unit = {
    header.encode(out)
    payload.encode(out)
  }

  def toBytes: Array[Byte] = {
    val out = ByteBuffer.allocate(length)
    encode(out)
    out.array().array.clone()
  }

  def toByteString: String = {
    HexFormat.of.formatHex(toBytes).toUpperCase
  }
}

object IpPacket {
  def fromBytes(ipPacket: Array[Byte]): IpPacket = {
    decode(ByteBuffer.wrap(ipPacket))
  }

  def fromByteString(ipPacket: String): IpPacket = {
    fromBytes(HexFormat.of.parseHex(ipPacket))
  }

  def decode(in: ByteBuffer): IpPacket = {
    decode(in, true)
  }

  def decode(in: ByteBuffer, ensureChecksum: Boolean): IpPacket = {
    in.mark
    val version = (in.get >>> Ipv4Header.VersionShift).toByte
    in.reset
    version match {
      case Ipv4Header.Version => Ipv4Packet.decode(in, ensureChecksum)
      case Ipv6Header.Version => Ipv6Packet.decode(in, ensureChecksum)
      case _ => throw new IllegalArgumentException("Not an IP data")
    }
  }
}

final case class Ipv4Packet(override val header: Ipv4Header, override val payload: Ipv4Payload) extends IpPacket {}

object Ipv4Packet {
  def decode(in: ByteBuffer, ensureChecksum: Boolean): Ipv4Packet = {
    val header = Ipv4Header.decode(in, ensureChecksum)
    val payload = Ipv4Payload.decode(in, ensureChecksum, header)
    new Ipv4Packet(header, payload)
  }
}

final case class Ipv6Packet(override val header: Ipv6Header, override val payload: Ipv6Payload) extends IpPacket {}

object Ipv6Packet {
  def decode(in: ByteBuffer, ensureChecksum: Boolean): Ipv6Packet = {
    val header = Ipv6Header.decode(in)
    val payload = Ipv6Payload.decode(in, ensureChecksum, header)
    new Ipv6Packet(header, payload)
  }
}

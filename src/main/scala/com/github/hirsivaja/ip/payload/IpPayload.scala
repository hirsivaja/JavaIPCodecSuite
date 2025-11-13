package com.github.hirsivaja.ip.payload

import com.github.hirsivaja.ip.header.{Ipv4Header, Ipv6Header}
import com.github.hirsivaja.ip.{IpProtocol, IpProtocols}
import com.github.hirsivaja.ip.payload.tcp.TcpSegment
import com.github.hirsivaja.ip.payload.udp.UdpDatagram

import java.nio.ByteBuffer

sealed trait IpPayload:
  val length: Int

  def encode(out: ByteBuffer): Unit

trait Ipv4Payload extends IpPayload

object Ipv4Payload {
  def decode(in: ByteBuffer, ensureChecksum: Boolean, header: Ipv4Header): Ipv4Payload = {
    header.protocol match {
      case IpProtocols.Tcp => TcpSegment.decode(in, ensureChecksum, header)
      case IpProtocols.Udp => UdpDatagram.decode(in, ensureChecksum, header)
      case _ => Generic.decode(in, header.protocol).asInstanceOf[Ipv4Payload]
    }
  }
}

trait Ipv6Payload extends IpPayload

object Ipv6Payload {
  def decode(in: ByteBuffer, ensureChecksum: Boolean, header: Ipv6Header): Ipv6Payload = {
    header.protocol match {
      case IpProtocols.Tcp => TcpSegment.decode(in, ensureChecksum, header)
      case IpProtocols.Udp => UdpDatagram.decode(in, ensureChecksum, header)
      case _ => Generic.decode(in, header.protocol).asInstanceOf[Ipv6Payload]
    }
  }
}

final case class Generic(protocol: IpProtocol, data: Array[Byte]) extends Ipv4Payload, Ipv6Payload {
  override val length: Int = data.length

  override def encode(out: ByteBuffer): Unit = out.put(data)
}

object Generic {
  def decode(in: ByteBuffer, protocol: IpProtocol): IpPayload = {
    val data = new Array[Byte](in.remaining)
    in.get(data)
    new Generic(protocol, data)
  }
}

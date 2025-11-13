package com.github.hirsivaja.ip.address

import java.net.InetAddress
import java.nio.ByteBuffer

sealed trait IpAddress {
  val length: Int

  def encode(out: ByteBuffer): Unit

  def toInetAddress: InetAddress
}

final case class Ipv4Address(address: Array[Byte]) extends IpAddress {
  require(address.length == Ipv4Address.Ipv4AddressLength)

  override val length: Int = Ipv4Address.Ipv4AddressLength

  override def encode(out: ByteBuffer): Unit = out.put(address)

  override def toInetAddress: InetAddress = InetAddress.getByAddress(address)

  override def toString: String = {
    val inetAddress = toInetAddress.toString
    if (inetAddress.startsWith("/")) {
      s"IPv4Address(${inetAddress.replaceFirst("/", "")})"
    } else {
      s"IPv4Address($inetAddress)"
    }
  }
}

object Ipv4Address {
  private val Ipv4AddressLength = 4

  def decode(in: ByteBuffer): Ipv4Address = {
    val address = new Array[Byte](Ipv4AddressLength)
    in.get(address)
    Ipv4Address(address)
  }
}

final case class Ipv6Address(address: Array[Byte]) extends IpAddress {
  require(address.length == Ipv6Address.Ipv6AddressLength)

  override val length: Int = Ipv6Address.Ipv6AddressLength

  override def encode(out: ByteBuffer): Unit = out.put(address)

  override def toInetAddress: InetAddress = InetAddress.getByAddress(address)

  override def toString: String = {
    val inetAddress = toInetAddress.toString
    if (inetAddress.startsWith("/")) {
      s"IPv6Address(${inetAddress.replaceFirst("/", "")})"
    } else {
      s"IPv6Address($inetAddress)"
    }
  }
}

object Ipv6Address {
  private val Ipv6AddressLength = 16

  def decode(in: ByteBuffer): Ipv6Address = {
    val address = new Array[Byte](Ipv6AddressLength)
    in.get(address)
    Ipv6Address(address)
  }
}

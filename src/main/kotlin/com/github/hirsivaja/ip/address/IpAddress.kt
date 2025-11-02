package com.github.hirsivaja.ip.address

import java.net.InetAddress
import java.nio.ByteBuffer

sealed interface IpAddress {
    fun encode(out: ByteBuffer)
    fun length(): Int
    fun toInetAddress(): InetAddress
    fun rawAddress(): ByteArray
}

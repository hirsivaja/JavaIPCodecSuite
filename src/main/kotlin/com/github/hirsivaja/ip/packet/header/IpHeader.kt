package com.github.hirsivaja.ip.packet.header

import com.github.hirsivaja.ip.protocol.IpProtocol
import java.nio.ByteBuffer

sealed interface IpHeader {
    fun encode(out: ByteBuffer)
    fun generatePseudoHeader(): ByteArray
    fun length(): Int
    fun pseudoHeaderLength(): Int
    fun protocol(): IpProtocol
}

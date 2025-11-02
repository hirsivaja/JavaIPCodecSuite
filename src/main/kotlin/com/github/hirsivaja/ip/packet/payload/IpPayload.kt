package com.github.hirsivaja.ip.packet.payload

import java.nio.ByteBuffer

sealed interface IpPayload {
    fun encode(out: ByteBuffer)
    fun length(): Int
}

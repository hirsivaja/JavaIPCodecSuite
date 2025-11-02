package com.github.hirsivaja.ip.packet.payload.udp

import java.nio.ByteBuffer

data class UdpHeader(val srcPort: UShort, val dstPort: UShort, val len: UShort, val checksum: Short) {

    fun encode(out: ByteBuffer) {
        out.putShort(srcPort.toShort())
        out.putShort(dstPort.toShort())
        out.putShort(len.toShort())
        out.putShort(checksum)
    }

    fun length() : Int {
        return UDP_HEADER_LEN
    }

    companion object {
        fun decode(buf: ByteBuffer) : UdpHeader {
            val srcPort = buf.getShort().toUShort()
            val dstPort = buf.getShort().toUShort()
            val len = buf.getShort().toUShort()
            val checksum = buf.getShort()
            return UdpHeader(srcPort, dstPort, len, checksum)
        }

        const val UDP_HEADER_LEN : Int = 8
    }
}

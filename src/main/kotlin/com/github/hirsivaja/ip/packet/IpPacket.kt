package com.github.hirsivaja.ip.packet

import com.github.hirsivaja.ip.packet.header.IpHeader
import com.github.hirsivaja.ip.packet.header.Ipv4Header
import com.github.hirsivaja.ip.packet.header.Ipv6Header
import com.github.hirsivaja.ip.packet.payload.IpPayload
import java.nio.ByteBuffer

sealed interface IpPacket {
    val header: IpHeader
    val payload: IpPayload

    fun encode(out: ByteBuffer) {
        header.encode(out)
        payload.encode(out)
    }

    fun length(): Int {
        return header.length() + payload.length()
    }

    fun toBytes() : ByteArray {
        val out = ByteBuffer.allocate(length())
        encode(out)
        val outBytes = out.array().copyOfRange(0, out.rewind().remaining())
        return outBytes
    }

    fun toByteString() : String {
        return toBytes().toHexString().uppercase()
    }

    companion object {
        fun fromBytes(ipPacket: ByteArray): IpPacket {
            return decode(ByteBuffer.wrap(ipPacket))
        }

        fun fromByteString(ipPacket: String): IpPacket {
            return fromBytes(ipPacket.hexToByteArray())
        }

        fun decode(buf: ByteBuffer) : IpPacket {
            return decode(buf, true)
        }

        fun decode(buf: ByteBuffer, ensureChecksum: Boolean) : IpPacket {
            buf.mark()
            val version = (buf.get().toInt() ushr Ipv4Header.VERSION_SHIFT)
            buf.reset()
            return when (version) {
                Ipv4Header.VERSION -> Ipv4Packet.decode(buf, ensureChecksum)
                Ipv6Header.VERSION -> Ipv6Packet.decode(buf, ensureChecksum)
                else -> throw IllegalArgumentException("Not an IP packet")
            }
        }
    }
}

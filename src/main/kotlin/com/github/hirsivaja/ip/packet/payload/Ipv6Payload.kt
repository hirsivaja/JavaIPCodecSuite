package com.github.hirsivaja.ip.packet.payload

import com.github.hirsivaja.ip.DataArray
import com.github.hirsivaja.ip.packet.header.Ipv6Header
import com.github.hirsivaja.ip.packet.payload.tcp.TcpSegment
import com.github.hirsivaja.ip.packet.payload.udp.UdpDatagram
import com.github.hirsivaja.ip.protocol.IpProtocol
import com.github.hirsivaja.ip.protocol.IpProtocols
import java.nio.ByteBuffer

interface Ipv6Payload : IpPayload {
    companion object {
        fun decode(buf: ByteBuffer, ensureChecksum: Boolean, header: Ipv6Header) : Ipv6Payload {
            return when (header.protocol()) {
                IpProtocols.TCP -> TcpSegment.decode(buf, ensureChecksum, header)
                IpProtocols.UDP -> UdpDatagram.decode(buf, ensureChecksum, header)
                else -> Generic.decode(buf, header.protocol())
            } as Ipv6Payload
        }
    }

    data class Generic(val protocol: IpProtocol, val data: DataArray) : Ipv6Payload {
        constructor(protocol: IpProtocol, data: ByteArray) : this(protocol, DataArray(data))

        override fun encode(out: ByteBuffer) {
            out.put(data.data)
        }

        override fun length(): Int {
            return data.length()
        }

        companion object {
            fun decode(buf: ByteBuffer, protocol: IpProtocol): IpPayload {
                val data = ByteArray(buf.remaining())
                buf[data]
                return Generic(protocol, data)
            }
        }
    }
}

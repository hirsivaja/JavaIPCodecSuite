package com.github.hirsivaja.ip.packet.header

import com.github.hirsivaja.ip.address.Ipv6Address
import com.github.hirsivaja.ip.protocol.IpProtocol
import java.nio.ByteBuffer

data class Ipv6Header(
    val ecn: Byte,
    val dscp: Byte,
    val flowLabel: Int,
    val payloadLength: UShort,
    val nextHeader: IpProtocol,
    val hopLimit: UByte,
    val sourceAddress: Ipv6Address,
    val destinationAddress: Ipv6Address
) : IpHeader {

    override fun encode(out: ByteBuffer) {
        val trafficClass = (ecn.toInt() and 0xFF or (dscp.toInt() shl DSCP_SHIFT)).toByte()
        var start = 0
        start = start or (VERSION shl VERSION_SHIFT)
        start = start or ((trafficClass.toInt() shl TRAFFIC_CLASS_SHIFT) and TRAFFIC_CLASS_MASK)
        start = start or (flowLabel and FLOW_LABEL_MASK)
        out.putInt(start)
        out.putShort(payloadLength.toShort())
        out.put(nextHeader.type.toByte())
        out.put(hopLimit.toByte())
        sourceAddress.encode(out)
        destinationAddress.encode(out)
    }

    override fun generatePseudoHeader(): ByteArray {
        val out = ByteBuffer.allocate(HEADER_LEN)
        sourceAddress.encode(out)
        destinationAddress.encode(out)
        out.putInt(payloadLength.toInt())
        out.put(0.toByte())
        out.put(0.toByte())
        out.put(0.toByte())
        out.put(nextHeader.type.toByte())
        val outBytes = ByteArray(HEADER_LEN)
        out.rewind()[outBytes]
        return outBytes
    }

    override fun length(): Int {
        return HEADER_LEN
    }

    override fun pseudoHeaderLength(): Int {
        return HEADER_LEN
    }

    override fun protocol(): IpProtocol {
        return nextHeader
    }

    companion object {
        fun decode(buf: ByteBuffer) : Ipv6Header {
            val start: Int = buf.getInt()
            val version = (start ushr VERSION_SHIFT).toByte()
            require(version.toInt() == VERSION) { "Unexpected version for IPv6 header! $version" }
            val ecnDscp = ((start and TRAFFIC_CLASS_MASK) ushr TRAFFIC_CLASS_SHIFT).toByte()
            val ecn: Byte = (ecnDscp.toInt() and 3).toByte()
            val dscp = (ecnDscp.toInt() ushr DSCP_SHIFT).toByte()
            val flowLabel = start and FLOW_LABEL_MASK
            val payloadLength: UShort = buf.getShort().toUShort()
            val nextHeader: IpProtocol = IpProtocol.fromType(buf.get().toUByte())
            val hopLimit: UByte = buf.get().toUByte()
            val sourceAddress: Ipv6Address = Ipv6Address.decode(buf)
            val destinationAddress: Ipv6Address = Ipv6Address.decode(buf)
            return Ipv6Header(ecn, dscp, flowLabel, payloadLength, nextHeader, hopLimit, sourceAddress, destinationAddress)
        }

        const val VERSION: Int = 6
        const val HEADER_LEN: Int = 40
        private const val VERSION_SHIFT: Int = 28
        private const val TRAFFIC_CLASS_MASK: Int = 0xFF00000
        private const val TRAFFIC_CLASS_SHIFT: Int = 20
        private const val DSCP_SHIFT: Int = 2
        private const val FLOW_LABEL_MASK: Int = 0xFFFFF
    }
}

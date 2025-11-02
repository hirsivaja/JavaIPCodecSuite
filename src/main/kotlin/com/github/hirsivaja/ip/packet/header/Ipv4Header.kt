package com.github.hirsivaja.ip.packet.header

import com.github.hirsivaja.ip.DataArray
import com.github.hirsivaja.ip.IpUtils
import com.github.hirsivaja.ip.address.Ipv4Address
import com.github.hirsivaja.ip.protocol.IpProtocol
import java.nio.ByteBuffer

data class Ipv4Header(
    val ihl: UByte,
    val ecn: Byte,
    val dscp: Byte,
    val len: UShort,
    val identification: Short,
    val flags: Byte,
    val fragmentOffset: UShort,
    val ttl: UByte,
    val protocol: IpProtocol,
    val srcIp: Ipv4Address,
    val dstIp: Ipv4Address,
    val options: DataArray
) : IpHeader {

    constructor(
        ihl: UByte,
        ecn: Byte,
        dscp: Byte,
        len: UShort,
        identification: Short,
        flags: Byte,
        fragmentOffset: UShort,
        ttl: UByte,
        protocol: IpProtocol,
        srcIp: Ipv4Address,
        dstIp: Ipv4Address,
        options: ByteArray
    ) : this(ihl, ecn, dscp, len, identification, flags, fragmentOffset, ttl, protocol, srcIp, dstIp, DataArray(options))

    override fun encode(out: ByteBuffer) {
        out.mark()
        val versionIhl = (VERSION shl VERSION_SHIFT or ((options.length() / 4) + 5)).toByte()
        out.put(versionIhl)
        val dscpEcn = (ecn.toInt() and 0xFF or (dscp.toInt() shl DSCP_SHIFT)).toByte()
        out.put(dscpEcn)
        out.putShort(len.toShort())
        out.putShort(identification)
        val flagsFragmentOffset = (fragmentOffset.toInt() or (flags.toInt() shl FLAGS_SHIFT)).toShort()
        out.putShort(flagsFragmentOffset)
        out.put(ttl.toByte())
        out.put(protocol.type.toByte())
        val checksumPosition = out.position()
        out.putShort(0.toShort())
        srcIp.encode(out)
        dstIp.encode(out)
        out.put(options.data)
        val position = out.position()
        val headerBytes = ByteArray(HEADER_LEN)
        out.reset()[headerBytes]
        val checksum = IpUtils.calculateInternetChecksum(headerBytes)
        out.putShort(checksumPosition, checksum)
        out.position(position)
    }

    override fun generatePseudoHeader(): ByteArray {
        val out = ByteBuffer.allocate(PSEUDO_HEADER_LEN)
        srcIp.encode(out)
        dstIp.encode(out)
        out.put(0.toByte())
        out.put(protocol.type.toByte())
        out.putShort((len.toInt() - HEADER_LEN - options.length()).toShort())
        val outBytes = ByteArray(PSEUDO_HEADER_LEN)
        out.rewind()[outBytes]
        return outBytes
    }

    override fun length(): Int {
        return HEADER_LEN + options.length()
    }

    override fun pseudoHeaderLength(): Int {
        return PSEUDO_HEADER_LEN
    }

    override fun protocol(): IpProtocol {
        return protocol
    }

    companion object {
        fun decode(buf: ByteBuffer, ensureChecksum: Boolean) : Ipv4Header {
            buf.mark()
            val ihlVersion: Byte = buf.get()
            val ihl = (ihlVersion.toInt() and 0x0F).toUByte()
            val version = (ihlVersion.toInt() ushr VERSION_SHIFT).toByte()
            require(version.toInt() == VERSION) { "Unexpected version for IPv4 header! $version" }
            val ecnDscp: Byte = buf.get()
            val ecn: Byte = (ecnDscp.toInt() and 3).toByte()
            val dscp = (ecnDscp.toInt() ushr DSCP_SHIFT).toByte()
            val len: UShort = buf.getShort().toUShort()
            val identification: Short = buf.getShort()
            val flagsFragmentOffset: Short = buf.getShort()
            val flags: Byte = (flagsFragmentOffset.toInt() ushr FLAGS_SHIFT).toByte()
            val fragmentOffset: UShort = (flagsFragmentOffset.toInt() and 0x1FFF).toUShort()
            val ttl: UByte = buf.get().toUByte()
            val protocol: IpProtocol = IpProtocol.fromType(buf.get().toUByte())
            buf.getShort() // Checksum
            val srcIp: Ipv4Address = Ipv4Address.decode(buf)
            val dstIp: Ipv4Address = Ipv4Address.decode(buf)
            buf.reset()
            val headerBytes = ByteArray(HEADER_LEN)
            buf[headerBytes]
            if(ensureChecksum) {
                IpUtils.ensureInternetChecksum(headerBytes)
            } else {
                IpUtils.verifyInternetChecksum(headerBytes)
            }
            val options = ByteArray((ihl.toInt() - 5) * 4)
            buf[options]
            return Ipv4Header(ihl, ecn, dscp, len, identification, flags, fragmentOffset, ttl, protocol, srcIp, dstIp, options)
        }

        const val VERSION: Int = 4
        const val HEADER_LEN: Int = 20
        const val PSEUDO_HEADER_LEN: Int = 12
        const val VERSION_SHIFT: Int = 4
        private const val DSCP_SHIFT: Int = 2
        private const val FLAGS_SHIFT: Int = 13
    }
}

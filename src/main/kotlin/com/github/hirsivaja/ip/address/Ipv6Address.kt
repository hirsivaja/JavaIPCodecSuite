package com.github.hirsivaja.ip.address

import com.github.hirsivaja.ip.DataArray
import java.net.InetAddress
import java.nio.ByteBuffer

data class Ipv6Address(val address: DataArray) : IpAddress {
    constructor(address: ByteArray) : this(DataArray(address))

    init {
        require(address.data.size == IPV6_ADDRESS_LEN) { "IPv6 address has to be 16 bytes long!" }
    }

    override fun encode(out: ByteBuffer) {
        out.put(address.data)
    }

    override fun length(): Int {
        return address.data.size
    }

    override fun toInetAddress(): InetAddress {
        return InetAddress.getByAddress(address.data)
    }

    override fun rawAddress(): ByteArray {
        return address.data
    }

    override fun toString(): String {
        val inetAddress = toInetAddress().toString().removePrefix("/")
        return "IPv6Address($inetAddress)"
    }

    companion object {
        fun decode(buf: ByteBuffer): Ipv6Address {
            val address = ByteArray(IPV6_ADDRESS_LEN)
            buf[address]
            return Ipv6Address(address)
        }

        const val IPV6_ADDRESS_LEN : Int = 16
    }
}

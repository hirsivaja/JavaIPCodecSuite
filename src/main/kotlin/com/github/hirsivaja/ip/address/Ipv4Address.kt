package com.github.hirsivaja.ip.address

import com.github.hirsivaja.ip.DataArray
import java.net.InetAddress
import java.nio.ByteBuffer

data class Ipv4Address(val address: DataArray) : IpAddress {
    constructor(address: ByteArray) : this(DataArray(address))

    init {
        require(address.data.size == IPV4_ADDRESS_LEN) { "IPv4 address has to be 4 bytes long!" }
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
        return "IPv4Address($inetAddress)"
    }

    companion object {
        fun decode(buf: ByteBuffer): Ipv4Address {
            val address = ByteArray(IPV4_ADDRESS_LEN)
            buf[address]
            return Ipv4Address(address)
        }

        const val IPV4_ADDRESS_LEN : Int = 4
    }
}

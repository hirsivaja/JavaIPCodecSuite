package com.github.hirsivaja.ip.protocol

sealed interface IpProtocol {
    val type: UByte

    companion object {
        fun fromType(type: UByte): IpProtocol {
            for (identifier in IpProtocols.entries) {
                if (identifier.type == type) {
                    return identifier
                }
            }
            return GenericIpProtocol(type)
        }
    }

    data class GenericIpProtocol(override val type: UByte) : IpProtocol
}

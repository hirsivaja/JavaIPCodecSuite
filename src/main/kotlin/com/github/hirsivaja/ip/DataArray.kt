package com.github.hirsivaja.ip

data class DataArray(val data: ByteArray) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as DataArray

        return data.contentEquals(other.data)
    }

    override fun hashCode(): Int {
        return data.contentHashCode()
    }

    override fun toString(): String {
        return "DataArray(" + data.toHexString().uppercase() + ")"
    }

    fun length() : Int {
        return data.size
    }
}

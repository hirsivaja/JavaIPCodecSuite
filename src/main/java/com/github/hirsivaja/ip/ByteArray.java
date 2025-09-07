package com.github.hirsivaja.ip;

import java.util.Arrays;

public record ByteArray(byte[] array) {
    public ByteArray {
        if(array == null) {
            throw new IllegalArgumentException("Array cannot be null!");
        }
    }

    public int length() {
        return array.length;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o){
            return true;
        }
        if (o == null || getClass() != o.getClass()){
            return false;
        }
        return Arrays.equals(this.array, ((ByteArray) o).array);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(array);
    }

    @Override
    public String toString() {
        return this.getClass().getSimpleName() + "[" + IpUtils.printHexBinary(array) + "]";
    }
}

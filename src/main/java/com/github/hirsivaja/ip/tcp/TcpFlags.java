package com.github.hirsivaja.ip.tcp;

public record TcpFlags(
        boolean isCongestionWindowReduced,
        boolean isEceFlag,
        boolean isUrgentPointerSignificant,
        boolean isAcknowledgementSignificant,
        boolean isPushFunction,
        boolean isReset,
        boolean isSynchronizeSequenceNumbers,
        boolean isLastPacket) {
    private static final byte CWR = (byte) 0x80;
    private static final byte ECE = (byte) 0x40;
    private static final byte URG = (byte) 0x20;
    private static final byte ACK = (byte) 0x10;
    private static final byte PSH = (byte) 0x08;
    private static final byte RST = (byte) 0x04;
    private static final byte SYN = (byte) 0x02;
    private static final byte FIN = (byte) 0x01;

    public byte toByte() {
        byte b = 0;
        if(isCongestionWindowReduced) {
            b |= CWR;
        }
        if(isEceFlag) {
            b |= ECE;
        }
        if(isUrgentPointerSignificant) {
            b |= URG;
        }
        if(isAcknowledgementSignificant) {
            b |= ACK;
        }
        if(isPushFunction) {
            b |= PSH;
        }
        if(isReset) {
            b |= RST;
        }
        if(isSynchronizeSequenceNumbers) {
            b |= SYN;
        }
        if(isLastPacket) {
            b |= FIN;
        }
        return b;
    }

    public static TcpFlags decode(byte flags) {
        boolean congestionWindowReduced = (flags & CWR & 0xFF) > 0;
        boolean eceFlag = (flags & ECE & 0xFF) > 0;
        boolean urgentPointerSignificant = (flags & URG & 0xFF) > 0;
        boolean acknowledgementSignificant = (flags & ACK & 0xFF) > 0;
        boolean pushFunction = (flags & PSH & 0xFF) > 0;
        boolean reset = (flags & RST & 0xFF) > 0;
        boolean synchronizeSequenceNumbers = (flags & SYN & 0xFF) > 0;
        boolean lastPacket = (flags & FIN & 0xFF) > 0;
        return new TcpFlags(congestionWindowReduced, eceFlag, urgentPointerSignificant, acknowledgementSignificant,
                pushFunction, reset, synchronizeSequenceNumbers, lastPacket);
    }

    public boolean isExplicitCongestionNotificationCapable() {
        return isSynchronizeSequenceNumbers && isEceFlag;
    }
}

package com.github.hirsivaja.ip.tcp;

public class TcpFlags {
    private static final byte CWR = (byte) 0x80;
    private static final byte ECE = (byte) 0x40;
    private static final byte URG = (byte) 0x20;
    private static final byte ACK = (byte) 0x10;
    private static final byte PSH = (byte) 0x08;
    private static final byte RST = (byte) 0x04;
    private static final byte SYN = (byte) 0x02;
    private static final byte FIN = (byte) 0x01;
    private final boolean congestionWindowReduced;
    private final boolean eceFlag;
    private final boolean urgentPointerSignificant;
    private final boolean acknowledgementSignificant;
    private final boolean pushFunction;
    private final boolean reset;
    private final boolean synchronizeSequenceNumbers;
    private final boolean lastPacket;

    @SuppressWarnings("squid:S00107")
    public TcpFlags(boolean congestionWindowReduced, boolean eceFlag, boolean urgentPointerSignificant,
                    boolean acknowledgementSignificant, boolean pushFunction, boolean reset,
                    boolean synchronizeSequenceNumbers, boolean lastPacket) {
        this.congestionWindowReduced = congestionWindowReduced;
        this.eceFlag = eceFlag;
        this.urgentPointerSignificant = urgentPointerSignificant;
        this.acknowledgementSignificant = acknowledgementSignificant;
        this.pushFunction = pushFunction;
        this.reset = reset;
        this.synchronizeSequenceNumbers = synchronizeSequenceNumbers;
        this.lastPacket = lastPacket;
    }

    public byte toByte() {
        byte b = 0;
        if(congestionWindowReduced) {
            b |= CWR;
        }
        if(eceFlag) {
            b |= ECE;
        }
        if(urgentPointerSignificant) {
            b |= URG;
        }
        if(acknowledgementSignificant) {
            b |= ACK;
        }
        if(pushFunction) {
            b |= PSH;
        }
        if(reset) {
            b |= RST;
        }
        if(synchronizeSequenceNumbers) {
            b |= SYN;
        }
        if(lastPacket) {
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

    public boolean isCongestionWindowReduced() {
        return congestionWindowReduced;
    }

    public boolean isEceFlag() {
        return eceFlag;
    }

    public boolean isUrgentPointerSignificant() {
        return urgentPointerSignificant;
    }

    public boolean isAcknowledgementSignificant() {
        return acknowledgementSignificant;
    }

    public boolean isPushFunction() {
        return pushFunction;
    }

    public boolean isReset() {
        return reset;
    }

    public boolean isSynchronizeSequenceNumbers() {
        return synchronizeSequenceNumbers;
    }

    public boolean isLastPacket() {
        return lastPacket;
    }

    public boolean isExplicitCongestionNotificationCapable() {
        return synchronizeSequenceNumbers && eceFlag;
    }

    @Override
    public String toString() {
        return this.getClass().getSimpleName() + "(" +
                "congestionWindowReduced=" + congestionWindowReduced +
                ", eceFlag=" + eceFlag +
                ", urgentPointerSignificant=" + urgentPointerSignificant +
                ", acknowledgementSignificant=" + acknowledgementSignificant +
                ", pushFunction=" + pushFunction +
                ", reset=" + reset +
                ", synchronizeSequenceNumbers=" + synchronizeSequenceNumbers +
                ", lastPacket=" + lastPacket +
                ")";
    }
}

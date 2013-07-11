package com.google.bitcoin.store;

/**
 * Thrown by the {@link WalletProtobufSerializer} when the serialized protocol buffer is either corrupted,
 * internally inconsistent or appears to be from the future.
 */
public class UnreadableWalletException extends Exception {
    public UnreadableWalletException(String s) {
        super(s);
    }

    public UnreadableWalletException(String s, Throwable t) {
        super(s, t);
    }
}

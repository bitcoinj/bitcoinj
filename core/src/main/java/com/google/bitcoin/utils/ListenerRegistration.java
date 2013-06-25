package com.google.bitcoin.utils;

import com.google.bitcoin.core.WalletEventListener;

import java.util.concurrent.Executor;

/**
* A simple wrapper around a listener and an executor.
*/
public class ListenerRegistration<T> {
    public T listener;
    public Executor executor;

    public ListenerRegistration(T listener, Executor executor) {
        this.listener = listener;
        this.executor = executor;
    }
}

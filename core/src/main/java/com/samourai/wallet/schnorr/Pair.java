package com.samourai.wallet.schnorr;

// clone of org.apache.commons.lang3.tuple.Pair;

public class Pair<K, V> {

    private K elementLeft = null;
    private V elementRight = null;

    protected Pair() {
        ;
    }

    public static <K, V> Pair<K, V> of(K elementLeft, V elementRight) {
        return new Pair<K, V>(elementLeft, elementRight);
    }

    public Pair(K elementLeft, V elementRight) {
        this.elementLeft = elementLeft;
        this.elementRight = elementRight;
    }

    public K getLeft() {
        return elementLeft;
    }

    public V getRight() {
        return elementRight;
    }

    public boolean equals(Pair<K, V> p) {
        return (this.elementLeft.equals(p.getLeft())) && (this.elementRight.equals(p.getRight()));
    }

}

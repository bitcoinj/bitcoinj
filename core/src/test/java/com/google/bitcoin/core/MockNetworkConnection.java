/*
 * Copyright 2011 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.bitcoin.core;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

/** Allows messages to be inserted and removed in a thread-safe manner. */
public class MockNetworkConnection implements NetworkConnection {
    private BlockingQueue<Object> inboundMessageQ;
    private BlockingQueue<Message> outboundMessageQ;

    private boolean waitingToRead;

    // Not used for anything except marking the shutdown point in the inbound queue.
    private Object disconnectMarker = new Object();
    private VersionMessage versionMessage;

    private static int fakePort = 1;
    private PeerAddress peerAddress;

    public MockNetworkConnection() {
        inboundMessageQ = new ArrayBlockingQueue<Object>(10);
        outboundMessageQ = new ArrayBlockingQueue<Message>(10);
        try {
            peerAddress = new PeerAddress(InetAddress.getLocalHost(), fakePort++);
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    public void ping() throws IOException {
    }

    public void shutdown() throws IOException {
        inboundMessageQ.add(disconnectMarker);
    }

    public synchronized void disconnect() throws IOException {
        inboundMessageQ.add(disconnectMarker);
    }

    public void exceptionOnRead(Exception e) {
        inboundMessageQ.add(e);
    }

    public Message readMessage() throws IOException, ProtocolException {
        try {
            // Notify popOutbound() that the network thread is now waiting to receive input. This is needed because
            // otherwise it's impossible to tell apart "thread decided to not write any message" from "thread is still
            // working on it".
            synchronized (this) {
                waitingToRead = true;
                notifyAll();
            }
            Object o = inboundMessageQ.take();
            // BUG 141: There is a race at this point: inbound queue can be empty at the same time as waitingToRead is
            // true, which is taken as an indication that all messages have been processed. In fact they have not.
            synchronized (this) {
                waitingToRead = false;
            }
            if (o instanceof IOException) {
                throw (IOException) o;
            } else if (o instanceof ProtocolException) {
                throw (ProtocolException) o;
            } else if (o instanceof Message) {
                return (Message) o;
            } else if (o == disconnectMarker) {
                throw new IOException("done");
            } else {
                throw new RuntimeException("Unknown object in inbound queue.");
            }
        } catch (InterruptedException e) {
            throw new IOException(e.getMessage());
        }
    }

    public void writeMessage(Message message) throws IOException {
        try {
            outboundMessageQ.put(message);
        } catch (InterruptedException e) {
            throw new IOException(e.getMessage());
        }
    }

    public void setVersionMessage(VersionMessage msg) {
        this.versionMessage = msg;
    }

    public void setVersionMessageForHeight(NetworkParameters params, int chainHeight) {
        versionMessage = new VersionMessage(params, chainHeight);
    }

    public VersionMessage getVersionMessage() {
        if (versionMessage == null) throw new RuntimeException("Need to call setVersionMessage first");
        return versionMessage;
    }


    public PeerAddress getPeerAddress() {
        return peerAddress;
    }

    /** Call this to add a message which will be received by the NetworkConnection user. Wakes up the network thread. */
    public void inbound(Message m) {
        try {
            inboundMessageQ.put(m);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Returns a message that has been written with writeMessage. Waits until the peer thread is sitting inside
     * readMessage() and has no further inbound messages to process. If at that point there is a message in the outbound
     * queue, takes and returns it. Otherwise returns null. Use popOutbound() for when there is no other thread.
     */
    public Message outbound() throws InterruptedException {
        synchronized (this) {
            while (!waitingToRead || inboundMessageQ.size() > 0) {
                wait();
            }
        }
        return popOutbound();
    }

    /**
     * Takes the most recently sent message or returns NULL if there are none waiting.
     */
    public Message popOutbound() throws InterruptedException {
        if (outboundMessageQ.peek() != null)
            return outboundMessageQ.take();
        else
            return null;
    }

    /**
     * Takes the most recently received message or returns NULL if there are none waiting.
     */
    public Object popInbound() throws InterruptedException {
        if (inboundMessageQ.peek() != null)
            return inboundMessageQ.take();
        else
            return null;
    }
    
    /** Convenience that does an inbound() followed by returning the value of outbound() */
    public Message exchange(Message m) throws InterruptedException {
        inbound(m);
        return outbound();
    }
}

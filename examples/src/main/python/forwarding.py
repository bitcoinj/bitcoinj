# An example of how to use Jython to implement the "Getting Started" tutorial app, which receives coins and simply
# sends them on (minus a fee).

__author__ = "richard 'ragmondo' green"

import sys

# Change this to point to where you have a copy of the bitcoinj.jar
sys.path.append(r"/path/to/bitcoinj-0.12-SNAPSHOT-bundled.jar")

# This is the address to forward all payments to. Change this (unless you want to send me some testnet coins)
my_address_text = "mzEjmna15T7DXj4HC9MBEG2UJzgFfEYtFo"

# 0 for instant send, 1 for a more realistic example
# if the wallet has no btc in it, then set to 1.
# if it has a confirmed balance in it, then you can set it to 0.
confirm_wait = 1

from org.bitcoinj.core import *

import org.bitcoinj.crypto.KeyCrypterException
import org.bitcoinj.params.MainNetParams
from org.bitcoinj.kits import WalletAppKit

from com.google.common.util.concurrent import FutureCallback
from com.google.common.util.concurrent import Futures

import java.io.File

import traceback,sys

def loud_exceptions(*args):
    def _trace(func):
        def wrapper(*args, **kwargs):
            try:
                func(*args, **kwargs)
            except Exception, e:
                traceback.print_exc()
                print "** python exception ",e
                raise
            except java.lang.Exception,e:
                traceback.print_exc()
                print "** java exception",e
                raise
        return wrapper

    if len(args) == 1 and callable(args[0]):
        return _trace(args[0])
    else:
        return _trace

@loud_exceptions
def forwardCoins(tx,w,pg,addr):
    v = tx.getValueSentToMe(w)
    amountToSend = v.subtract(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE)
   # v_bigint = java.math.BigInteger(str(v))
    sr = w.sendCoins(pg, addr, amountToSend)

class SenderListener(AbstractWalletEventListener):
    def __init__(self,pg,address):
        super(SenderListener,self). __init__()
        self.peerGroup = pg
        self.address = address

    @loud_exceptions
    def onCoinsReceived(self, w, tx, pb, nb):
        print "tx received", tx
        v = tx.getValueSentToMe(w)

        class myFutureCallback(FutureCallback):
            @loud_exceptions
            def onSuccess(selfx, txn):
                forwardCoins(tx,w,self.peerGroup, self.address)

        print "creating %s confirm callback..." % (confirm_wait)
        Futures.addCallback(tx.getConfidence().getDepthFuture(confirm_wait), myFutureCallback())

if __name__ == "__main__":
    params = com.google.bitcoin.params.TestNet3Params.get()
    my_address = Address(params,my_address_text)
    filePrefix = "forwarding-service-testnet"
    f = java.io.File(".")
    kit = WalletAppKit(params, f, filePrefix);
    print "starting and initialising (please wait).."
    kit.startAsync()
    kit.awaitRunning()
    pg = kit.peerGroup()
    wallet = kit.wallet()
    sendToAddress = kit.wallet().currentReceiveKey().toAddress(params)
    print "send test coins to ", sendToAddress, "qrcode - http://qrickit.com/api/qr?d=%s" % (sendToAddress) # no affiliation with qrickit..
    sl = SenderListener(pg,my_address)
    wallet.addEventListener(sl)
    print "finished initialising .. now in main event loop"
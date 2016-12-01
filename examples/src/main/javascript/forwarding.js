// For more info on how to run/control logging look at demo.js
//
// This example shows how to implement the forwarding service demo from the Getting Started tutorial.

var bcj = org.bitcoinj;
var params = bcj.params.TestNet3Params.get();

// Address where we'll send received coins (minus the miner fee)
var FORWARD_TO = "mfZCyhQUQXy2S91hnGepdaJxfaNjMg15AV";  // faucet.xeno-genesis.com

// Make logging more compact.
bcj.utils.BriefLogFormatter.init();

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

var forwardingAddr = new bcj.core.Address(params, FORWARD_TO);

var kit = new bcj.kits.WalletAppKit(params, new java.io.File("/tmp"), "forwarding-demo");
print("Starting up ...");
kit.startAsync()
kit.awaitRunning()

var wallet = kit.wallet();
var myAddr = wallet.currentReceiveAddress()
var uri = "bitcoin:" + myAddr;
print("Send coins to: " + myAddr);
print("QRcode: http://qrickit.com/api/qr?d=" + uri);

wallet.allowSpendingUnconfirmedTransactions()

var listener = Java.extend(bcj.wallet.listeners.AbstractWalletEventListener);
wallet.addEventListener(new listener() {
    onCoinsReceived: function(wallet, tx, prevBalance, newBalance) {
        print("Received money! " + newBalance.toFriendlyString());
        var sendReq = bcj.wallet.SendRequest.emptyWallet(forwardingAddr);
        var sendResult = wallet.sendCoins(sendReq);
        print("Sending back in tx " + sendResult.tx.hash);
    }
});

print("Press Ctrl-C to stop");
java.lang.Thread.sleep(1000 * 60 * 60);  // One hour.

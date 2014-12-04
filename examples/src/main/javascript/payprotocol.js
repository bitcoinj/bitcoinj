// Example app that creates a minimal BIP70 payment request with a multisig output, and then prints it to base64.

var bcj = org.bitcoinj;
var protos = org.bitcoin.protocols.payments.Protos;
var pbuf = com.google.protobuf;

var details = protos.PaymentDetails.newBuilder();
details.time = new Date().value;
var output = protos.Output.newBuilder();

var scriptBytes = bcj.script.ScriptBuilder.createMultiSigOutputScript(2, [new bcj.core.ECKey(), new bcj.core.ECKey()]).program;
// ... or to a regular address output:
// var scriptBytes = bcj.script.ScriptBuilder.createOutputScript(new bcj.core.ECKey().toAddress(bcj.params.MainNetParams.get())).program;

output.script = pbuf.ByteString.copyFrom(scriptBytes);
details.addOutputs(output);

var request = protos.PaymentRequest.newBuilder();
request.serializedPaymentDetails = details.build().toByteString();

var bits = request.build().toByteArray();
var b64 = java.util.Base64.getEncoder().encodeToString(bits);
print(b64);


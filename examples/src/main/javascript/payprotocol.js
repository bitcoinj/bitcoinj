/*
 * Copyright by the original author or authors.
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


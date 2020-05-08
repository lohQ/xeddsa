import 'package:flutter/material.dart';
import 'package:xeddsa/xeddsa.dart';
import 'package:cryptography/cryptography.dart';

void main() => runApp(MyApp());

class MyApp extends StatefulWidget {
  @override
  _MyAppState createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {

  KeyPair myIdentity;
  KeyPair myPreKey;
  List<int> identityPrivateKeyBytes;
  List<int> signature;
  bool verified;

  @override
  void initState(){
    super.initState();
    signature = null;
    verified = null;
    generateKeyPairs();
  }

  void generateKeyPairs() async {
    setState(() {
      signature = null;
      verified = null;      
    });
    x25519.newKeyPair().then((kp){
      setState(() {myIdentity = kp;});
      myIdentity.privateKey.extract().then((bytes){
        setState(() {identityPrivateKeyBytes = bytes;});
    });});
    x25519.newKeyPair().then((kp){
      setState(() {myPreKey = kp;});
    });
  }

  void testSign(){
    if(myIdentity == null || myPreKey == null){
      return;
    }
    Xeddsa().sign(
      identityPrivateKey: myIdentity.privateKey, 
      identityPublicKey: myIdentity.publicKey, 
      message: myPreKey.publicKey.bytes).then(
        (newSignature){
          print("new signature at main: "+newSignature.toString());
          setState(() {
            signature = List.from(newSignature);
            print("updated signature at main: "+signature.toString());
          });
        })
        .catchError((e){print("error in test sign: $e");});
  }

  void testVerify(){
    if(signature == null){
      return;
    }
    bool newVerified = Xeddsa().verify(
      signature: signature, 
      publicIdentityKey: myIdentity.publicKey,
      message: myPreKey.publicKey.bytes);
    if(verified != newVerified){
      setState((){verified = newVerified;});
    }
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: const Text('Xeddsa example app'),
        ),
        body: ListView(
          padding: EdgeInsets.all(10),
          children: <Widget>[
            RaisedButton(
              child: Text("Generate New Key Pairs"),
              onPressed: generateKeyPairs,),
            Text(identityPrivateKeyBytes == null
              ? "(identity private key)"
              : identityPrivateKeyBytes.toString()),
            Text(myIdentity == null
              ? "(identity public key)"
              : myIdentity.publicKey.bytes.toString()),
            Text(myPreKey == null
              ? "(message to be encrypted)"
              : myPreKey.publicKey.bytes.toString()),
            RaisedButton(
              child: Text("Generate Signature"),
              onPressed: testSign),
            Text(signature == null
              ? "(signature)"
              : signature.toString()),
            RaisedButton(
              child: Text("Verify Signature"),
              onPressed: testVerify),
            Text(verified == null
              ? "(verification result)"
              : "verification result is $verified"),
          ],
        )
      ),
    );
  }
}

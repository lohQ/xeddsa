import 'package:flutter/material.dart';
import 'package:xeddsa/xeddsa.dart';
import 'package:cryptography/cryptography.dart';

void main() => runApp(MyApp());

class MyApp extends StatefulWidget {
  @override
  _MyAppState createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {

  void testXeddsa() async {
    final KeyPair myIdentity = await x25519.newKeyPair();
    final KeyPair myPreKey = await x25519.newKeyPair();

    Signature signature = await Xeddsa().sign(
      identityPrivateKey: myIdentity.privateKey, 
      identityPublicKey: myIdentity.publicKey, 
      message: myPreKey.publicKey.bytes);

    bool isVerified = Xeddsa().verify(
      signature: signature, 
      identityPublicKey: myIdentity.publicKey, 
      message: myPreKey.publicKey.bytes);

    if(isVerified){
      print("successfully verified!");
    }
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: const Text('Xeddsa example app'),
        ),
        body: Center(
          child: RaisedButton(
            onPressed: testXeddsa,
            child: Text("Test Xeddsa with new keypair")),
        ),
      ),
    );
  }
}

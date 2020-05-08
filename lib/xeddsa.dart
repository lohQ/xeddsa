import 'dart:ffi'; // For FFI
import 'dart:io';

import 'package:cryptography/cryptography.dart';
import 'package:ffi/ffi.dart';

final DynamicLibrary xeddsaLib = Platform.isAndroid
    ? DynamicLibrary.open("libxeddsa.so")
    : DynamicLibrary.process();

typedef xeddsa_sign_func = Int32 Function(
  Pointer<Uint8> signature, 
  Pointer<Uint8> privateKey, 
  Pointer<Uint8> message, 
  Uint64 messageLen, 
  Pointer<Uint8> random);
typedef XeddsaSign = int Function(
  Pointer<Uint8> signature, 
  Pointer<Uint8> privateKey, 
  Pointer<Uint8> message, 
  int messageLen, 
  Pointer<Uint8> random);

typedef xeddsa_verify_func = Int32 Function(
  Pointer<Uint8> signature, 
  Pointer<Uint8> publicKey, 
  Pointer<Uint8> message, 
  Uint64 messageLen);
typedef XeddsaVerify = int Function(
  Pointer<Uint8> signature, 
  Pointer<Uint8> privateKey, 
  Pointer<Uint8> message, 
  int messageLen);

final xeddsaSignPointer = xeddsaLib
  .lookup<NativeFunction<xeddsa_sign_func>>('xed25519_sign');
final xeddsaSign = xeddsaSignPointer.asFunction<XeddsaSign>();

final xeddsaVerifyPointer = xeddsaLib
  .lookup<NativeFunction<xeddsa_verify_func>>('xed25519_verify');
final xeddsaVerify = xeddsaVerifyPointer.asFunction<XeddsaVerify>();

class Xeddsa{

  void _copyBytesToPointer(Pointer<Uint8> pointer, List<int> kBytes, [String nameOfBytes]) async {
    try{
      for(int i = 0; i < kBytes.length; i++){
        pointer[i] = kBytes[i];
      }
    }catch (e){
      print("error copying bytes for $nameOfBytes: $e");
    }
  }

  List<int> _getBytesOfLength(Pointer<Uint8> pointer, int len){
    try{
      final resultingList = pointer.asTypedList(len);
      return resultingList;
    }catch(e){
      print("failed to return array of length $len from pointer");
      return null;
    }
  }

  void _freePointers(List<Pointer<Uint8>> pointerList){
    for(final pointer in pointerList){
      free(pointer);
    }
  }

  Future<Signature> sign(
    {PrivateKey identityPrivateKey, PublicKey identityPublicKey, 
     List<int> message}) async {

    final privPointer = allocate<Uint8>(count: 32);
    final pubPointer = allocate<Uint8>(count: 32);
    final messageLen = message.length;
    final msgPointer = allocate<Uint8>(count: messageLen);
    final randomPointer = allocate<Uint8>(count: 64);
    final signaturePointer = allocate<Uint8>(count: 64);
    final pointerList = [privPointer, pubPointer, msgPointer, randomPointer, signaturePointer];
    
    _copyBytesToPointer(privPointer, await identityPrivateKey.extract(), "private identity key");
    _copyBytesToPointer(pubPointer, identityPublicKey.bytes, "public identity key");
    _copyBytesToPointer(msgPointer, message, "message");
    // TODO: debug why the program crashed when random is used
    final randomListInt = List.filled(64, 0);
    _copyBytesToPointer(randomPointer, randomListInt, "random");

    try{
      final signResult = xeddsaSign(signaturePointer, privPointer, msgPointer, messageLen, randomPointer);
      if(signResult == 0){
        print("successfully signed");
        final signatureBytes = _getBytesOfLength(signaturePointer, 64);
        _freePointers(pointerList);
        return Signature(signatureBytes, publicKey: identityPublicKey);
      }else{
        print("failed to sign: return value $signResult");
      }
    }catch(e){
      print("error signing: $e");
    }
    _freePointers(pointerList);
    return null;
  }

  bool verify({Signature signature, PublicKey identityPublicKey, List<int> message}){
    final signaturePointer = allocate<Uint8>(count: 64);
    final publicKeyPointer = allocate<Uint8>(count: 32);
    final msgLen = message.length;
    final messagePointer = allocate<Uint8>(count: msgLen);
    final pointerList = [signaturePointer, publicKeyPointer, messagePointer];
    _copyBytesToPointer(signaturePointer, signature.bytes, "signature");
    _copyBytesToPointer(publicKeyPointer, identityPublicKey.bytes, "public identity key");
    _copyBytesToPointer(messagePointer, message, "message");
    try{
      final verifyResult = xeddsaVerify(signaturePointer, publicKeyPointer, messagePointer, msgLen);
      if(verifyResult == 0){
        _freePointers(pointerList);
        return true;
      }else{
        print("failed to verify: return value $verifyResult");
      }
    }catch(e){
      print("error verifying: $e");
    }
    _freePointers(pointerList);
    return false;
  }

}


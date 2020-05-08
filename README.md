# xeddsa

A simple flutter plugin project providing ffi for xeddsa digital signature algorithm written in C.

## note

1. Currently only supports Android. IOS will require extra configuration (see https://flutter.dev/docs/development/platform-integration/c-interop)

2. The random bytes passed into the xed25519_sign function, if used, will cause the app to crash. Hence tweaked the implementation to not using this parameter. (TODO: Debug this)

3. The signing and verifying process is rather slow. (TODO: at least 10 signing/verifying in one second) 

## Getting Started

This project is a starting point for a Flutter
[plug-in package](https://flutter.dev/developing-packages/),
a specialized package that includes platform-specific implementation code for
Android and/or iOS.

For help getting started with Flutter, view our 
[online documentation](https://flutter.dev/docs), which offers tutorials, 
samples, guidance on mobile development, and a full API reference.

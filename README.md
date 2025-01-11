## Usage

```dart
import 'package:flutter_rsa/flutter_rsa.dart';

void main() {
  // generate key
  final keyPair = RSAEncryption().generateKeyPair();

  // encode key to pem
  final publicKeyPem = RSAEncryption().encodePublicKeyToPem(keyPair.publicKey);
  final privateKeyPem =
      RSAEncryption().encodePrivateKeyToPem(keyPair.privateKey);

  // decode pem to key
  final publicKey = RSAEncryption().decodePublicKeyFromPem(publicKeyPem);
  final privateKey = RSAEncryption().decodePrivateKeyFromPem(privateKeyPem);
}
```
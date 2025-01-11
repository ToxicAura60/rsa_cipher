## Usage

```dart
import 'package:flutter_rsa/flutter_rsa.dart';

void main() {
  // generate key
  final keyPair = RSACipher().generateKeyPair();

  // encode key to pem
  final publicKeyPem = RSACipher().encodePublicKeyToPem(keyPair.publicKey);
  final privateKeyPem =
      RSACipher().encodePrivateKeyToPem(keyPair.privateKey);

  // decode pem to key
  final publicKey = RSACipher().decodePublicKeyFromPem(publicKeyPem);
  final privateKey = RSACipher().decodePrivateKeyFromPem(privateKeyPem);
}
```
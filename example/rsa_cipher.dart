import 'package:rsa_cipher/rsa_cipher.dart';

void main() {
  // generate key
  final keyPair = RsaCipher().generateKeyPair();

  // encode key to pem
  final publicKeyPem = RsaCipher().encodePublicKeyToPem(keyPair.publicKey);
  final privateKeyPem = RsaCipher().encodePrivateKeyToPem(keyPair.privateKey);

  // decode pem to key
  final publicKey = RsaCipher().decodePublicKeyFromPem(publicKeyPem);
  final privateKey = RsaCipher().decodePrivateKeyFromPem(privateKeyPem);
}

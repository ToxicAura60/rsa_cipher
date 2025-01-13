import 'package:pointycastle/export.dart';
import 'package:rsa_cipher/rsa_cipher.dart';

void main() {
  // generate key
  final keyPair = RsaCipher().generateKeyPair();

  // encode key to pem
  final publicKeyPem = RsaCipher().keyToPem<RSAPublicKey>(keyPair.publicKey);
  final privateKeyPem = RsaCipher().keyToPem<RSAPrivateKey>(keyPair.privateKey);

  // decode pem to key
  final publicKey = RsaCipher().keyFromPem<RSAPublicKey>(publicKeyPem);
  final privateKey = RsaCipher().keyFromPem<RSAPrivateKey>(privateKeyPem);
}

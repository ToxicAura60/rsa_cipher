import 'package:pointycastle/export.dart';
import 'package:rsa_cipher/rsa_cipher.dart';

void main() async {
  // generate key
  final keyPair = RsaCipher().generateKeyPair();

  // encode key to pem
  final publicKeyPem = RsaCipher().keyToPem<RSAPublicKey>(keyPair.publicKey);
  final privateKeyPem = RsaCipher().keyToPem<RSAPrivateKey>(keyPair.privateKey);

  // decode pem to key
  final publicKey = RsaCipher().keyFromPem<RSAPublicKey>(publicKeyPem);
  final privateKey = RsaCipher().keyFromPem<RSAPrivateKey>(privateKeyPem);

  // save pem to file
  RsaCipher().storeKeyToFile(filePath: '.../public_key.pem', key: publicKey);
  RsaCipher().storeKeyToFile(filePath: '.../private_key.pem', key: privateKey);

  // get key from file
  final publicKeyFromFile =
      RsaCipher().retrieveKeyFromFile<RSAPublicKey>('.../public_key.pem');
  final privateKeyFromFile =
      RsaCipher().retrieveKeyFromFile<RSAPrivateKey>('.../private_key.pem');
}

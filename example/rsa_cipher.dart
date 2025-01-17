import 'package:path_provider/path_provider.dart';
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
  final directory = await getApplicationDocumentsDirectory();
  RsaCipher().storeKeyToFile(
      filePath: '${directory.path}/public_key.pem', key: publicKey);
  RsaCipher().storeKeyToFile(
      filePath: '${directory.path}/private_key.pem', key: privateKey);

  // get key from file
  final publicKeyFromFile = RsaCipher()
      .retrieveKeyFromFile<RSAPublicKey>('${directory.path}/public_key.pem');
  final privateKeyFromFile = RsaCipher()
      .retrieveKeyFromFile<RSAPrivateKey>('${directory.path}/private_key.pem');
}

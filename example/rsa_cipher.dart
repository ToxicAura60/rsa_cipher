import 'package:path_provider/path_provider.dart';
import 'package:pointycastle/export.dart';
import 'package:rsa_cipher/rsa_cipher.dart';

void main() async {
  // generate key
  final keyPair = RsaCipher().generateKeyPair();

  // encode key to pem
  final publicKeyPem = RsaCipher().keyToPem<RSAPublicKey>(keyPair.publicKey);
  final privateKeyPem = RsaCipher().keyToPem<RSAPrivateKey>(keyPair.privateKey);

  // save pem to file
  final directory = await getApplicationDocumentsDirectory();
  RsaCipher().savePemToFile(
      filePath: '${directory.path}/private_key.pem', pem: publicKeyPem);

  // get key from file
  final publicKeyFromFile = RsaCipher()
      .keyFromFile<RSAPrivateKey>('${directory.path}/private_key.pem');

  // decode pem to key
  final publicKey = RsaCipher().keyFromPem<RSAPublicKey>(publicKeyPem);
  final privateKey = RsaCipher().keyFromPem<RSAPrivateKey>(privateKeyPem);
}

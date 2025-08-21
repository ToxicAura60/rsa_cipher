import 'package:rsa_cipher/rsa_cipher.dart';

void main() async {
  // generate key
  final keyPair = RsaCipher().generateKeyPair();

  // encode key to pem
  final publicKeyPem = keyPair.publicKey.toPem();
  final privateKeyPem = keyPair.privateKey.toPem();

  // decode pem to key
  final publicKey = PublicKey.fromPem(publicKeyPem);
  final privateKey = PrivateKey.fromPem(privateKeyPem);

  // encrypt text
  final cipherText = RsaCipher().encrypt(
    plaintext: "hello",
    publicKey: publicKey,
  );

  // decrypt text
  final plainText = RsaCipher().decrypt(
    ciphertext: cipherText,
    privateKey: privateKey,
  );
}

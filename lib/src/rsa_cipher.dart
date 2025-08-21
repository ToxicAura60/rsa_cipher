import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:pointycastle/export.dart' as pc;
import 'models/models.dart';

class RsaCipher {
  /// Generates a secure random number generator with Fortuna algorithm.
  /// This is used to seed the RSA key generator with strong randomness.
  ///
  /// Returns a [pc.SecureRandom] object seeded with random data.
  pc.SecureRandom _getSecureRandom() {
    final secureRandom = pc.FortunaRandom();
    final random = Random.secure();
    List<int> seeds = [];
    for (int i = 0; i < 32; i++) {
      seeds.add(random.nextInt(256));
    }
    secureRandom.seed(pc.KeyParameter(Uint8List.fromList(seeds)));
    return secureRandom;
  }

  /// Generates an RSA key pair consisting of a public and private key.
  /// The RSA key pair is generated with a key size of 2048 bits and
  /// a public exponent of 65537 using the RSA key generator with strong randomness.
  ///
  /// Returns the generated RSA key pair, with both public and private keys.
  KeyPair generateKeyPair({int keySize = 2048}) {
    final rsaParams = pc.RSAKeyGeneratorParameters(
      BigInt.parse('65537'),
      keySize,
      64,
    );
    final paramsWithRandom = pc.ParametersWithRandom(
      rsaParams,
      _getSecureRandom(),
    );

    final keyGen = pc.RSAKeyGenerator();
    keyGen.init(paramsWithRandom);

    final keyPair = keyGen.generateKeyPair();

    return KeyPair(
      privateKey: PrivateKey.fromRSAPrivateKey(keyPair.privateKey),
      publicKey: PublicKey.fromRSAPublicKey(keyPair.publicKey),
    );
  }

  /// Encrypts plaintext using RSA and the provided public key.
  /// The encryption is performed with the RSA/OAEP scheme.
  ///
  /// [plaintext] The plaintext to encrypt.
  /// [publicKey] The RSA public key used for encryption.
  /// Returns the base64-encoded ciphertext.
  String encrypt({
    required String plaintext,
    required pc.RSAPublicKey publicKey,
  }) {
    final cipher = pc.AsymmetricBlockCipher('RSA/OAEP')
      ..init(true, pc.PublicKeyParameter<pc.RSAPublicKey>(publicKey));
    final cipherText = cipher.process(Uint8List.fromList(plaintext.codeUnits));

    return base64.encode(cipherText);
  }

  /// Decrypts a base64-encoded ciphertext using RSA and the provided private key.
  /// The decryption is performed with the RSA/OAEP scheme.
  ///
  /// [ciphertext] The base64-encoded ciphertext to decrypt.
  /// [privateKey] The RSA private key used for decryption.
  /// Returns the decrypted plaintext as a string.
  String decrypt({
    required String ciphertext,
    required pc.RSAPrivateKey privateKey,
  }) {
    final cipher = pc.AsymmetricBlockCipher('RSA/OAEP')
      ..init(false, pc.PrivateKeyParameter<pc.RSAPrivateKey>(privateKey));
    var decryptedText = cipher.process(
      Uint8List.fromList(base64.decode(ciphertext)),
    );

    return String.fromCharCodes(decryptedText);
  }
}

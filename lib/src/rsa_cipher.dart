import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';
import "package:pointycastle/export.dart";
import "package:asn1lib/asn1lib.dart";

class RsaCipher {
  // Generates a secure random number generator with Fortuna algorithm.
  // This is used to seed the RSA key generator with strong randomness.
  SecureRandom _secureRandom() {
    final secureRandom = SecureRandom('Fortuna');
    var random = Random.secure();
    List<int> seeds = [];
    for (int i = 0; i < 32; i++) {
      seeds.add(random.nextInt(255));
    }
    secureRandom.seed(KeyParameter(Uint8List.fromList(seeds)));
    return secureRandom;
  }

  // Generates an RSA key pair (public and private keys) with a 2048-bit key size.
  // Uses RSA key generator with the public exponent of 65537.
  AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> generateKeyPair() {
    var rsaParams = RSAKeyGeneratorParameters(BigInt.parse('65537'), 2048, 64);
    final paramsWithRandom = ParametersWithRandom(rsaParams, _secureRandom());

    final keyGen = KeyGenerator('RSA');
    keyGen.init(paramsWithRandom);

    final pair = keyGen.generateKeyPair();
    final public = pair.publicKey as RSAPublicKey;
    final private = pair.privateKey as RSAPrivateKey;

    return AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>(public, private);
  }

  // Converts a PEM-encoded key (public or private) into an RSA key object.
  // The PEM format is stripped of headers and decoded from base64.
  T keyFromPem<T extends RSAAsymmetricKey>(String pem) {
    final data = pem.replaceAll(RegExp(r'(\r\n|\n|\r|\\n|-----.*?-----)'), "");
    if (pem.startsWith("-----BEGIN PUBLIC KEY-----")) {
      return _publicKeyFromPem(base64.decode(data)) as T;
    } else if (pem.startsWith("-----BEGIN RSA PRIVATE KEY-----")) {
      return _privateKeyFromPem(base64.decode(data)) as T;
    } else {
      throw ArgumentError('Invalid key');
    }
  }

  // Converts an RSA key (public or private) to its PEM-encoded string representation.
  // PEM format includes headers and base64-encoded key data.
  String keyToPem<T extends RSAAsymmetricKey>(T rsaKey) {
    if (rsaKey is RSAPublicKey) {
      return _publicKeyToPem(rsaKey as RSAPublicKey);
    } else if (rsaKey is RSAPrivateKey) {
      return _privateKeyToPem(rsaKey as RSAPrivateKey);
    } else {
      throw ArgumentError('Invalid key');
    }
  }

  // Stores an RSA key (public or private) to a file in PEM format.
  // The file is written synchronously to the provided file path.
  void storeKeyToFile<T extends RSAAsymmetricKey>({
    required String filePath,
    required T key,
  }) {
    String pem;
    if (key is RSAPublicKey) {
      pem = _publicKeyToPem(key);
    } else if (key is RSAPrivateKey) {
      pem = _privateKeyToPem(key);
    } else {
      throw ArgumentError('Invalid key');
    }
    File(filePath).writeAsStringSync(pem);
  }

  // Retrieves an RSA key (public or private) from a PEM file.
  // If the file exists, it reads the PEM content, decodes it, and returns the key.
  T? retrieveKeyFromFile<T extends RSAAsymmetricKey>(String filePath) {
    final file = File(filePath);
    if (file.existsSync()) {
      final pem = file.readAsStringSync();
      return keyFromPem<T>(pem);
    } else {
      return null;
    }
  }

  // Decodes a PEM-encoded public key and converts it into an RSAPublicKey object.
  // The public key is extracted and parsed from the ASN.1 structure in the PEM data.
  RSAPublicKey _publicKeyFromPem(Uint8List data) {
    var topLevelSeq = ASN1Parser(data).nextObject() as ASN1Sequence;
    var publicKeyBitString = topLevelSeq.elements[1] as ASN1BitString;

    ASN1Sequence publicKeySeq = ASN1Parser(publicKeyBitString.contentBytes())
        .nextObject() as ASN1Sequence;
    var modulus = publicKeySeq.elements[0] as ASN1Integer;
    var exponent = publicKeySeq.elements[1] as ASN1Integer;

    RSAPublicKey rsaPublicKey =
        RSAPublicKey(modulus.valueAsBigInteger, exponent.valueAsBigInteger);

    return rsaPublicKey;
  }

  // Decodes a PEM-encoded private key and converts it into an RSAPrivateKey object.
  // The private key is extracted and parsed from the ASN.1 structure in the PEM data.
  RSAPrivateKey _privateKeyFromPem(Uint8List data) {
    var topLevelSeq = ASN1Parser(data).nextObject() as ASN1Sequence;
    var privateKeyOctetString = topLevelSeq.elements[2] as ASN1OctetString;

    var privateKeySequence = ASN1Parser(privateKeyOctetString.contentBytes())
        .nextObject() as ASN1Sequence;

    var modulus = privateKeySequence.elements[1] as ASN1Integer;
    var privateExponent = privateKeySequence.elements[3] as ASN1Integer;
    var p = privateKeySequence.elements[4] as ASN1Integer;
    var q = privateKeySequence.elements[5] as ASN1Integer;

    RSAPrivateKey rsaPrivateKey = RSAPrivateKey(
      modulus.valueAsBigInteger,
      privateExponent.valueAsBigInteger,
      p.valueAsBigInteger,
      q.valueAsBigInteger,
    );

    return rsaPrivateKey;
  }

  // Encrypts plaintext using RSA public key and OAEP padding scheme.
  // The resulting ciphertext is encoded in base64 format.
  String encrypt({required String plaintext, required RSAPublicKey publicKey}) {
    final cipher = AsymmetricBlockCipher('RSA/OAEP')
      ..init(true, PublicKeyParameter<RSAPublicKey>(publicKey));
    final cipherText = cipher.process(Uint8List.fromList(plaintext.codeUnits));

    return base64.encode(cipherText);
  }

  // Decrypts a base64-encoded ciphertext using RSA private key and OAEP padding scheme.
  // The decrypted plaintext is returned as a string.
  String decrypt(String ciphertext, RSAPrivateKey privateKey) {
    final cipher = AsymmetricBlockCipher('RSA/OAEP')
      ..init(false, PrivateKeyParameter<RSAPrivateKey>(privateKey));
    var decryptedText =
        cipher.process(Uint8List.fromList(base64.decode(ciphertext)));

    return String.fromCharCodes(decryptedText);
  }

  // Converts an RSA public key to its PEM-encoded string representation.
  // The public key is encoded as an ASN.1 sequence and then base64-encoded.
  String _publicKeyToPem(RSAPublicKey publicKey) {
    final ASN1Sequence algorithmSequence = ASN1Sequence();
    final ASN1Object algorithm = ASN1Object.fromBytes(Uint8List.fromList(
        [0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0x1]));
    var parameters = ASN1Object.fromBytes(Uint8List.fromList([0x5, 0x0]));
    algorithmSequence.add(algorithm);
    algorithmSequence.add(parameters);

    var publicKeySequence = ASN1Sequence();
    publicKeySequence.add(ASN1Integer(publicKey.modulus!));
    publicKeySequence.add(ASN1Integer(publicKey.exponent!));
    var publicKeySeqBitString =
        ASN1BitString(Uint8List.fromList(publicKeySequence.encodedBytes));

    var topLevelSeq = ASN1Sequence();
    topLevelSeq.add(algorithmSequence);
    topLevelSeq.add(publicKeySeqBitString);
    var data = base64.encode(topLevelSeq.encodedBytes);

    return "-----BEGIN PUBLIC KEY-----\n$data\n-----END PUBLIC KEY-----";
  }

  // Converts an RSA private key to its PEM-encoded string representation.
  // The private key is encoded as an ASN.1 sequence and then base64-encoded.
  String _privateKeyToPem(RSAPrivateKey privateKey) {
    var algorithmSequence = ASN1Sequence();
    var algorithm = ASN1Object.fromBytes(Uint8List.fromList(
        [0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0x1]));
    var parameters = ASN1Object.fromBytes(Uint8List.fromList([0x5, 0x0]));
    algorithmSequence.add(algorithm);
    algorithmSequence.add(parameters);

    var privateKeySequence = ASN1Sequence();
    var version = ASN1Integer(BigInt.from(0));
    var modulus = ASN1Integer(privateKey.modulus!);
    var publicExponent = ASN1Integer(BigInt.parse('65537'));
    var privateExponent = ASN1Integer(privateKey.exponent!);
    var prime1 = ASN1Integer(privateKey.p!);
    var prime2 = ASN1Integer(privateKey.q!);
    var exponent1 =
        ASN1Integer(privateKey.exponent! % (privateKey.p! - BigInt.from(1)));
    var exponent2 =
        ASN1Integer(privateKey.exponent! % (privateKey.q! - BigInt.from(1)));
    var coefficient = ASN1Integer(privateKey.q!.modInverse(privateKey.p!));
    privateKeySequence.add(version);
    privateKeySequence.add(modulus);
    privateKeySequence.add(publicExponent);
    privateKeySequence.add(privateExponent);
    privateKeySequence.add(prime1);
    privateKeySequence.add(prime2);
    privateKeySequence.add(exponent1);
    privateKeySequence.add(exponent2);
    privateKeySequence.add(coefficient);
    final publicKeySeqOctetString =
        ASN1OctetString(Uint8List.fromList(privateKeySequence.encodedBytes));

    final topLevelSequence = ASN1Sequence();
    topLevelSequence.add(version);
    topLevelSequence.add(algorithmSequence);
    topLevelSequence.add(publicKeySeqOctetString);
    final data = base64.encode(topLevelSequence.encodedBytes);

    return "-----BEGIN RSA PRIVATE KEY-----\n$data\n-----END RSA PRIVATE KEY-----";
  }
}

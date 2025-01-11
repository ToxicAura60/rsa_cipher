import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import "package:pointycastle/export.dart";
import "package:asn1lib/asn1lib.dart";

class RsaCipher {
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

  Uint8List decodePEM(String pem) {
    var startsWith = [
      "-----BEGIN PUBLIC KEY-----",
      "-----BEGIN RSA PRIVATE KEY-----",
    ];
    var endsWith = [
      "-----END PUBLIC KEY-----",
      "-----END RSA PRIVATE KEY-----",
    ];

    for (var s in startsWith) {
      if (pem.startsWith(s)) {
        pem = pem.substring(s.length);
      }
    }

    for (var s in endsWith) {
      if (pem.endsWith(s)) {
        pem = pem.substring(0, pem.length - s.length);
      }
    }

    pem = pem.replaceAll('\n', '');
    pem = pem.replaceAll('\r', '');

    return base64.decode(pem);
  }

  RSAPublicKey decodePublicKeyFromPem(pemString) {
    var publicKeyDER = decodePEM(pemString);
    var topLevelSeq = ASN1Parser(publicKeyDER).nextObject() as ASN1Sequence;
    var publicKeyBitString = topLevelSeq.elements[1] as ASN1BitString;

    ASN1Sequence publicKeySeq = ASN1Parser(publicKeyBitString.contentBytes())
        .nextObject() as ASN1Sequence;
    var modulus = publicKeySeq.elements[0] as ASN1Integer;
    var exponent = publicKeySeq.elements[1] as ASN1Integer;

    RSAPublicKey rsaPublicKey =
        RSAPublicKey(modulus.valueAsBigInteger, exponent.valueAsBigInteger);

    return rsaPublicKey;
  }

  RSAPrivateKey decodePrivateKeyFromPem(pemString) {
    final privateKeyDER = decodePEM(pemString);
    var topLevelSeq = ASN1Parser(privateKeyDER).nextObject() as ASN1Sequence;
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

  String encrypt({required String plaintext, required RSAPublicKey publicKey}) {
    final cipher = AsymmetricBlockCipher('RSA/OAEP')
      ..init(true, PublicKeyParameter<RSAPublicKey>(publicKey));
    final cipherText = cipher.process(Uint8List.fromList(plaintext.codeUnits));

    return base64.encode(cipherText);
  }

  String decrypt(String ciphertext, RSAPrivateKey privateKey) {
    final cipher = AsymmetricBlockCipher('RSA/OAEP')
      ..init(false, PrivateKeyParameter<RSAPrivateKey>(privateKey));
    var decryptedText =
        cipher.process(Uint8List.fromList(base64.decode(ciphertext)));

    return String.fromCharCodes(decryptedText);
  }

  String encodePublicKeyToPem(RSAPublicKey publicKey) {
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
    var dataBase64 = base64.encode(topLevelSeq.encodedBytes);

    return """-----BEGIN PUBLIC KEY-----\r\n$dataBase64\r\n-----END PUBLIC KEY-----""";
  }

  String encodePrivateKeyToPem(RSAPrivateKey privateKey) {
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
    final dataBase64 = base64.encode(topLevelSequence.encodedBytes);

    return """-----BEGIN RSA PRIVATE KEY-----\r\n$dataBase64\r\n-----END RSA PRIVATE KEY-----""";
  }
}

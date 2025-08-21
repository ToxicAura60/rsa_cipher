import 'package:pointycastle/pointycastle.dart' as pc;
import 'package:asn1lib/asn1lib.dart';
import 'dart:typed_data';
import 'dart:convert';

class PrivateKey extends pc.RSAPrivateKey {
  PrivateKey(
    super.modulus,
    super.privateExponent,
    super.p,
    super.q, [
    super.publicExponent,
  ]);

  factory PrivateKey.fromRSAPrivateKey(pc.RSAPrivateKey privateKey) {
    return PrivateKey(
      privateKey.modulus!,
      privateKey.privateExponent!,
      privateKey.p,
      privateKey.q,
    );
  }

  factory PrivateKey.fromPem(String pem) {
    final data = base64.decode(
      pem.replaceAll(RegExp(r'(\r\n|\n|\r|\\n|-----.*?-----)'), ""),
    );
    var topLevelSeq = ASN1Parser(data).nextObject() as ASN1Sequence;
    var privateKeyOctetString = topLevelSeq.elements[2] as ASN1OctetString;

    var privateKeySequence =
        ASN1Parser(privateKeyOctetString.contentBytes()).nextObject()
            as ASN1Sequence;

    var modulus = privateKeySequence.elements[1] as ASN1Integer;
    var privateExponent = privateKeySequence.elements[3] as ASN1Integer;
    var p = privateKeySequence.elements[4] as ASN1Integer;
    var q = privateKeySequence.elements[5] as ASN1Integer;

    return PrivateKey(
      modulus.valueAsBigInteger,
      privateExponent.valueAsBigInteger,
      p.valueAsBigInteger,
      q.valueAsBigInteger,
    );
  }

  String toPem() {
    var algorithmSequence = ASN1Sequence();
    var algorithm = ASN1Object.fromBytes(
      Uint8List.fromList([
        0x6,
        0x9,
        0x2a,
        0x86,
        0x48,
        0x86,
        0xf7,
        0xd,
        0x1,
        0x1,
        0x1,
      ]),
    );
    var parameters = ASN1Object.fromBytes(Uint8List.fromList([0x5, 0x0]));
    algorithmSequence.add(algorithm);
    algorithmSequence.add(parameters);

    var privateKeySequence = ASN1Sequence();
    var version = ASN1Integer(BigInt.from(0));
    var modulus = ASN1Integer(this.modulus!);
    var publicExponent = ASN1Integer(BigInt.parse('65537'));
    var privateExponent = ASN1Integer(exponent!);
    var prime1 = ASN1Integer(p!);
    var prime2 = ASN1Integer(q!);
    var exponent1 = ASN1Integer(exponent! % (p! - BigInt.from(1)));
    var exponent2 = ASN1Integer(exponent! % (q! - BigInt.from(1)));
    var coefficient = ASN1Integer(q!.modInverse(p!));
    privateKeySequence.add(version);
    privateKeySequence.add(modulus);
    privateKeySequence.add(publicExponent);
    privateKeySequence.add(privateExponent);
    privateKeySequence.add(prime1);
    privateKeySequence.add(prime2);
    privateKeySequence.add(exponent1);
    privateKeySequence.add(exponent2);
    privateKeySequence.add(coefficient);
    final publicKeySeqOctetString = ASN1OctetString(
      Uint8List.fromList(privateKeySequence.encodedBytes),
    );

    final topLevelSequence = ASN1Sequence();
    topLevelSequence.add(version);
    topLevelSequence.add(algorithmSequence);
    topLevelSequence.add(publicKeySeqOctetString);
    final data = base64.encode(topLevelSequence.encodedBytes);

    return "-----BEGIN RSA PRIVATE KEY-----\n$data\n-----END RSA PRIVATE KEY-----";
  }
}

import 'package:pointycastle/pointycastle.dart' as pc;
import "package:asn1lib/asn1lib.dart";
import 'dart:typed_data';
import 'dart:convert';

class PublicKey extends pc.RSAPublicKey {
  PublicKey(super.modulus, super.exponent);

  factory PublicKey.fromRSAPublicKey(pc.RSAPublicKey publicKey) {
    return PublicKey(publicKey.modulus!, publicKey.exponent!);
  }

  factory PublicKey.fromPem(String pem) {
    final data = base64.decode(
      pem.replaceAll(RegExp(r'(\r\n|\n|\r|\\n|-----.*?-----)'), ""),
    );
    final topLevelSeq = ASN1Parser(data).nextObject() as ASN1Sequence;
    final publicKeyBitString = topLevelSeq.elements[1] as ASN1BitString;

    ASN1Sequence publicKeySeq =
        ASN1Parser(publicKeyBitString.contentBytes()).nextObject()
            as ASN1Sequence;
    var modulus = publicKeySeq.elements[0] as ASN1Integer;
    var exponent = publicKeySeq.elements[1] as ASN1Integer;

    return PublicKey(modulus.valueAsBigInteger, exponent.valueAsBigInteger);
  }

  String toPem() {
    final ASN1Sequence algorithmSequence = ASN1Sequence();
    final ASN1Object algorithm = ASN1Object.fromBytes(
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

    var publicKeySequence = ASN1Sequence();
    publicKeySequence.add(ASN1Integer(modulus!));
    publicKeySequence.add(ASN1Integer(exponent!));
    var publicKeySeqBitString = ASN1BitString(
      Uint8List.fromList(publicKeySequence.encodedBytes),
    );

    var topLevelSeq = ASN1Sequence();
    topLevelSeq.add(algorithmSequence);
    topLevelSeq.add(publicKeySeqBitString);
    var data = base64.encode(topLevelSeq.encodedBytes);

    return "-----BEGIN PUBLIC KEY-----\n$data\n-----END PUBLIC KEY-----";
  }
}

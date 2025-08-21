import 'private_key.dart';
import 'public_key.dart';

class KeyPair {
  KeyPair({required this.privateKey, required this.publicKey});
  final PrivateKey privateKey;
  final PublicKey publicKey;
}

using System;
using System.Collections.Generic;
using System.Text;

using Libsecp256k1Zkp.Net;

namespace Example
{
    unsafe class Program
    {
        static void Main(string[] args)
        {
            using var secp256K1 = new Secp256k1();
            using var pedersen = new Pedersen();
            using var bulletProof = new BulletProof();
            using var edsaAdaptor = new EcdsaAdaptor();
            using var rangeProof = new RangeProof();
            using var schnorr = new Schnorr();
            
            var keyPair = secp256K1.GenerateKeyPair(true);

            var msg = "Message for signing";
            var msgBytes = Encoding.UTF8.GetBytes(msg);
            var msgHash = System.Security.Cryptography.SHA256.Create().ComputeHash(msgBytes);

            var sigIn = schnorr.Sign(msgHash, keyPair.PrivateKey);

            var p = secp256K1.SerializePublicKey(keyPair.PublicKey);
            
            
            var valid = schnorr.Verify(sigIn, msgHash, p);
            var sigOut = schnorr.Serialize(sigIn);
             sigOut = schnorr.Parse(sigIn);
            
            
            // ulong value = 1000;
            // var blinding = secp256K1.CreatePrivateKey();
            // var commit = pedersen.Commit(value, blinding);
            // var @struct = bulletProof.GenProof(value, blinding, (byte[])blinding.Clone(), (byte[])blinding.Clone(), null, null);
            // var success = bulletProof.Verify(commit, @struct.proof, null);
            //
            //
            // var blinding1 = secp256K1.CreatePrivateKey();
            // var commit1 = pedersen.Commit(9, blinding1);
            // var msg = "Message for signing";
            // var msgBytes = Encoding.UTF8.GetBytes(msg);
            // var msgHash = System.Security.Cryptography.SHA256.Create().ComputeHash(msgBytes);
            // var proof = rangeProof.Proof(0, 9, blinding1, commit1, msgHash);
            // var verified = rangeProof.Verify(commit1, proof);

            EdsaAdaptorSample();
        }
        static void SignWithPubKeyFromCommitment()
        {
            using var secp256K1 = new Secp256k1();
            using var pedersen = new Pedersen();

            static string ToHex(byte[] data)
            {
                return BitConverter.ToString(data).Replace("-", string.Empty);
            }

            var blinding = secp256K1.CreatePrivateKey();
            var commit = pedersen.Commit(0, blinding);

            var msg = "Message for signing";
            var msgBytes = Encoding.UTF8.GetBytes(msg);
            var msgHash = System.Security.Cryptography.SHA256.Create().ComputeHash(msgBytes);

            var sig = secp256K1.Sign(msgHash, blinding);

            var pubKey = pedersen.ToPublicKey(commit);

            var t = secp256K1.Verify(sig, msgHash, pubKey);

            var actualPubKey = secp256K1.CreatePublicKey(blinding);

            var eq = ToHex(pubKey) == ToHex(actualPubKey);
        }


        static void VerifyBatchSigning()
        {
            using var secp256k1 = new Secp256k1();
            using var schnorrSig = new Schnorr();

            var signatures = new List<byte[]>();
            var messages = new List<byte[]>();
            var publicKeys = new List<byte[]>();

            for (int i = 0; i < 10; i++)
            {
                var keyPair = secp256k1.GenerateKeyPair();

                var msg = $"Message for signing {i}";
                var msgBytes = Encoding.UTF8.GetBytes(msg);
                var msgHash = System.Security.Cryptography.SHA256.Create().ComputeHash(msgBytes);

                var sig = schnorrSig.Sign(msgHash, keyPair.PrivateKey);

                signatures.Add(sig);
                publicKeys.Add(keyPair.PublicKey);

                msg = $"Message for signing wrong {i}";
                msgBytes = Encoding.UTF8.GetBytes(msg);
                msgHash = System.Security.Cryptography.SHA256.Create().ComputeHash(msgBytes);

                messages.Add(msgHash);
            }

            var valid = schnorrSig.VerifyBatch(signatures, messages, publicKeys);
        }
        
        static string ToHex(byte[] data)
        {
            return BitConverter.ToString(data).Replace("-", string.Empty);
        }

        static byte[] ToBytes(string value)
        {
            return Encoding.UTF8.GetBytes(value);
        }
        
        /// <summary>
        /// Steps:
        /// - Alice and Bob agree on known values; timelock t_1 and t_2; bitcoin address (Alice,Bob) with x currency (s_Bob, v_Alice) public keys.
        /// - Alice and Bob share an adaptor signatures with each other, encrypted privately with (sk, s, m)
        /// - Alice and Bob can verify said adaptor.
        /// - Knowing this Alice (can refund on x currency) or Bob can claim/refund or timelock to release funds. 
        /// - Bob creates the transaction with script for btc transactions.
        /// - Alice sees that Bob created btc transaction, moves funds on x currency (s_B, v_A) address safely and can refund.
        ///
        /// Bitcoin script 2-2 multi-sig:
        /// - Alice signs her own address and Bob's address, releasing secret v_a to Bob. Bob controls s_a + v_a
        /// - Bob can do the same, releasing secret s_b to Alice which now controls v_a + s_b
        /// </summary>
        static void EdsaAdaptorSample()
        {
            using var secp256K1 = new Secp256k1();
            using var edsaAdaptor = new EcdsaAdaptor();
            
            // BTC keys
            var aliceBitcoin = secp256K1.GenerateKeyPair();
            var bobBitcoin = secp256K1.GenerateKeyPair();
            
            // keys
            var aliceView = secp256K1.GenerateKeyPair();
            var bobSpend = secp256K1.GenerateKeyPair();
            
            // When referring to secret keys we use lowercase e.g. x; when referring to public keys we use uppercase e.g. X
            // Alice is the party that holds x currency and wants bitcoin in exchange; Bob is the party that holds bitcoin and wants x currency in exchange.
            // s denoting spend key and v denoting view key.
            // Public shared keys (s_B, v_A)
            // Secret keys (s_b, v_a)
            // Only someone with knowledge of both s_b + v_a will be able to spend the shared output.

            // Assumptions:
            // the amounts being exchanged; and
            // the value of the absolute timelocks, t_1 and t_2, where t_2 > t_1.

            // Bob will construct a address where Alice will eventually lock up her coins in a shared output (S_b + V_a),
            // constructed using the corresponding public keys.
            
            // btc htlc
            // OP_IF <AliceRefundLockTime> OP_CLTV OP_DROP OP_DUP OP_HASH160 <AliceAddress> OP_EQUALVERIFY OP_CHECKSIG 
            //     OP_ELSE 
            // OP_IF OP_SIZE 32 OP_EQUALVERIFY OP_HASH256 <SecretHash> OP_EQUALVERIFY 2 <AliceAddress> <BobAddress> 2 OP_CHECKMULTISIG 
            // OP_ELSE <BobRefundLockTime> OP_CSV OP_DROP 2 <AliceAddress> <BobAddress> 2 OP_CHECKMULTISIG
            //     OP_ENDIF 
            // OP_ENDIF            
            
            
            // Simple message used for signing.
            var msgHash = System.Security.Cryptography.SHA256.Create().ComputeHash(ToBytes("Swapping btc for x currency"));

            // +++++++++++++++ ALICE
            Console.WriteLine("+++++++++++++++ Alice self test +++++++++++++++");
            // Prove to the other party that X and Y actually do share the same secret key x, without revealing its value.
            var aliceAdaptorSig162 = edsaAdaptor.Encrypt(aliceBitcoin.PrivateKey, aliceView.PublicKey, msgHash);
            var verifyAliceAdaptorSig162 = edsaAdaptor.Verify(aliceAdaptorSig162, aliceBitcoin.PublicKey , msgHash, aliceView.PublicKey);
            Console.WriteLine("alice verify adaptorSig162:                    " + verifyAliceAdaptorSig162);

            // Signature that is used to leak the secret key if either, party signs the transaction.
            var aliceDecryptSig = edsaAdaptor.Decrypt(aliceView.PrivateKey, aliceAdaptorSig162);
            Console.WriteLine("alice's sig:                                   " + secp256K1.Verify(aliceDecryptSig, msgHash, aliceBitcoin.PublicKey));
            
            // Recover the secret key form ether party, that signed the transaction.
            var recoverAlice = edsaAdaptor.Recover(aliceDecryptSig, aliceAdaptorSig162, aliceView.PublicKey);
            Console.WriteLine("alice view private key:                        " + ToHex(aliceView.PrivateKey));
            Console.WriteLine("alice view recover private key:                " + ToHex(recoverAlice));
            
            Console.WriteLine();
            Console.WriteLine();
            
            // +++++++++++++++ BOB
            Console.WriteLine("+++++++++++++++ Bob self test +++++++++++++++");
            var bobAdaptorSig162 = edsaAdaptor.Encrypt(bobBitcoin.PrivateKey, bobSpend.PublicKey, msgHash);
            var verifyBobAdaptorSig162 = edsaAdaptor.Verify(bobAdaptorSig162, bobBitcoin.PublicKey, msgHash, bobSpend.PublicKey);
            Console.WriteLine("bob verify adaptorSig162:                      " + verifyBobAdaptorSig162);
            
            var bobDecryptSig = edsaAdaptor.Decrypt(bobSpend.PrivateKey, bobAdaptorSig162);
            Console.WriteLine("bob's sig:                                     " + secp256K1.Verify(bobDecryptSig, msgHash, bobBitcoin.PublicKey));

            var recoverBob = edsaAdaptor.Recover(bobDecryptSig, bobAdaptorSig162, bobSpend.PublicKey);
            Console.WriteLine("bob spend private key:                         " + ToHex(bobSpend.PrivateKey));
            Console.WriteLine("bob spend recover private key:                 " + ToHex(recoverBob));

            Console.WriteLine();
            Console.WriteLine();
            
            // +++++++++++++++ Fair Exchange of Signatures Without a Trusted Party
            Console.WriteLine("+++++++++++++++ Fair Exchange of Signatures Without a Trusted Party +++++++++++++++");
            // Alice generates her signature encryption under a public encryption key she herself generates and sends the key and the ciphertext to Bob.
            var aliceAdaptorSig1623 = edsaAdaptor.Encrypt(aliceBitcoin.PrivateKey, aliceView.PublicKey, msgHash);
            
            // Bob verifies 
            var verifyBobAdaptorSig1623 = edsaAdaptor.Verify(aliceAdaptorSig1623, aliceBitcoin.PublicKey, msgHash, aliceView.PublicKey);
            Console.WriteLine("bob verifies alice's encrypted sig:            " + verifyBobAdaptorSig1623);
            
            // Bob responds by generating a signature encrypted under the same key.
            var bobAdaptorSig1623 = edsaAdaptor.Encrypt(bobBitcoin.PrivateKey, aliceView.PublicKey, msgHash);
            
            // Alice decrypts this signature and publishes it on chain.
            var aliceDecryptSig2 = edsaAdaptor.Decrypt(aliceView.PrivateKey, bobAdaptorSig1623);
            Console.WriteLine("alice publishes sig on bob's bitcoin address:  " + secp256K1.Verify(aliceDecryptSig2, msgHash, bobBitcoin.PublicKey));
            
            // Bob is able to recover the Alice’s decryption key and decrypt the signature from the ciphertext given to him by Alice.
            var recoverFromAlice = edsaAdaptor.Recover(aliceDecryptSig2, bobAdaptorSig1623, aliceView.PublicKey);
            Console.WriteLine("bob recovers alice's private view key:         " + ToHex(recoverFromAlice));
        }
    }
}

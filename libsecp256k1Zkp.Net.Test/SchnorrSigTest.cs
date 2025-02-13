﻿using System.Collections.Generic;
using System.Text;

using Xunit;

namespace Libsecp256k1Zkp.Net.Test
{
    public class SchnorrSigTest
    {
        [Fact]
        public void Schnorrsig_Serialize()
        {
            using (var secp256k1 = new Secp256k1())
            using (var schnorr = new Schnorr())
            {
                var keyPair = secp256k1.GenerateKeyPair();

                var msg = "Message for signing";
                var msgBytes = Encoding.UTF8.GetBytes(msg);
                var msgHash = System.Security.Cryptography.SHA256.Create().ComputeHash(msgBytes);

                var sigIn = schnorr.Sign(msgHash, keyPair.PrivateKey);
                var sigOut = schnorr.Serialize(sigIn);

                Assert.NotNull(sigOut);
                Assert.InRange(sigOut.Length, 0, Constant.SIGNATURE_SIZE);
            }
        }

        [Fact]
        public void Schnorrsig_Parse()
        {
            using (var secp256k1 = new Secp256k1())
            using (var schnorr = new Schnorr())
            {
                var keyPair = secp256k1.GenerateKeyPair();

                var msg = "Message for signing";
                var msgBytes = Encoding.UTF8.GetBytes(msg);
                var msgHash = System.Security.Cryptography.SHA256.Create().ComputeHash(msgBytes);

                var sig = schnorr.Sign(msgHash, keyPair.PrivateKey);
                var sigOut = schnorr.Parse(sig);

                Assert.NotNull(sigOut);
                Assert.InRange(sigOut.Length, 0, Constant.SIGNATURE_SIZE);
            }
        }

        [Fact]
        public void Schnorrsig_Sign()
        {
            using (var secp256k1 = new Secp256k1())
            using (var schnorr = new Schnorr())
            {
                var keyPair = secp256k1.GenerateKeyPair();

                var msg = "Message for signing";
                var msgBytes = Encoding.UTF8.GetBytes(msg);
                var msgHash = System.Security.Cryptography.SHA256.Create().ComputeHash(msgBytes);

                var sig = schnorr.Sign(msgHash, keyPair.PrivateKey);

                Assert.NotNull(sig);
                Assert.InRange(sig.Length, 0, Constant.SIGNATURE_SIZE);
            }
        }

        [Fact]
        public void Schnorrsig_Verify()
        {
            using (var secp256k1 = new Secp256k1())
            using (var schnorr = new Schnorr())
            {
                var keyPair = secp256k1.GenerateKeyPair();

                var msg = "Message for signing";
                var msgBytes = Encoding.UTF8.GetBytes(msg);
                var msgHash = System.Security.Cryptography.SHA256.Create().ComputeHash(msgBytes);

                var sig = schnorr.Sign(msgHash, keyPair.PrivateKey);

                Assert.NotNull(sig);
                Assert.InRange(sig.Length, 0, Constant.SIGNATURE_SIZE);

                var valid = schnorr.Verify(sig, msgHash, keyPair.PublicKey);

                Assert.True(valid);
            }
        }

        [Fact]
        public void Schnorrsig_Wrong_Verify()
        {
            using (var secp256k1 = new Secp256k1())
            using (var schnorr = new Schnorr())
            {
                var keyPair = secp256k1.GenerateKeyPair();

                var msg = "Message for signing";
                var msgBytes = Encoding.UTF8.GetBytes(msg);
                var msgHash = System.Security.Cryptography.SHA256.Create().ComputeHash(msgBytes);

                var sig = schnorr.Sign(msgHash, keyPair.PrivateKey);

                Assert.NotNull(sig);
                Assert.InRange(sig.Length, 0, Constant.SIGNATURE_SIZE);

                msg = "Wrong message for signing";
                msgBytes = Encoding.UTF8.GetBytes(msg);
                msgHash = System.Security.Cryptography.SHA256.Create().ComputeHash(msgBytes);

                var valid = schnorr.Verify(sig, msgHash, keyPair.PublicKey);

                Assert.False(valid);
            }
        }

        [Fact]
        public void Schnorrsig_Verify_Batch()
        {
            using (var secp256k1 = new Secp256k1())
            using (var schnorr = new Schnorr())
            {
                var signatures = new List<byte[]>();
                var messages = new List<byte[]>();
                var publicKeys = new List<byte[]>();

                for (int i = 0; i < 10; i++)
                {
                    var keyPair = secp256k1.GenerateKeyPair();

                    var msg = $"Message for signing {i}";
                    var msgBytes = Encoding.UTF8.GetBytes(msg);
                    var msgHash = System.Security.Cryptography.SHA256.Create().ComputeHash(msgBytes);

                    var sig = schnorr.Sign(msgHash, keyPair.PrivateKey);

                    Assert.NotNull(sig);
                    Assert.InRange(sig.Length, 0, Constant.SIGNATURE_SIZE);

                    signatures.Add(sig);
                    messages.Add(msgHash);
                    publicKeys.Add(keyPair.PublicKey);
                }

                var valid = schnorr.VerifyBatch(signatures, messages, publicKeys);

                Assert.True(valid);
            }
        }

        [Fact]
        public void Schnorrsig_Wrong_Verify_Batch()
        {
            using (var secp256k1 = new Secp256k1())
            using (var schnorr = new Schnorr())
            {
                var signatures = new List<byte[]>();
                var messages = new List<byte[]>();
                var publicKeys = new List<byte[]>();

                for (int i = 0; i < 10; i++)
                {
                    var keyPair = secp256k1.GenerateKeyPair();

                    var msg = $"Message for signing {i}";
                    var msgBytes = Encoding.UTF8.GetBytes(msg);
                    var msgHash = System.Security.Cryptography.SHA256.Create().ComputeHash(msgBytes);

                    var sig = schnorr.Sign(msgHash, keyPair.PrivateKey);

                    Assert.NotNull(sig);
                    Assert.InRange(sig.Length, 0, Constant.SIGNATURE_SIZE);

                    signatures.Add(sig);
                    publicKeys.Add(keyPair.PublicKey);

                    msg = $"Message for signing wrong {i}";
                    msgBytes = Encoding.UTF8.GetBytes(msg);
                    msgHash = System.Security.Cryptography.SHA256.Create().ComputeHash(msgBytes);

                    messages.Add(msgHash);
                }

                var valid = schnorr.VerifyBatch(signatures, messages, publicKeys);

                Assert.False(valid);
            }
        }
    }
}

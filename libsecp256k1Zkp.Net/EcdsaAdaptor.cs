using System;

using static Libsecp256k1Zkp.Net.Secp256k1Native;
using static Libsecp256k1Zkp.Net.EdsaAaptorSignatureNative;

namespace Libsecp256k1Zkp.Net
{
    public class EcdsaAdaptor: IDisposable
    {
        public IntPtr Context { get; private set; }
        
        public EcdsaAdaptor()
        {
            Context = secp256k1_context_create((uint)(Flags.SECP256K1_CONTEXT_SIGN | Flags.SECP256K1_CONTEXT_VERIFY));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="secKey32"></param>
        /// <param name="encPubKey"></param>
        /// <param name="msg32"></param>
        /// <returns></returns>
        public byte[]? Encrypt(byte[] secKey32, byte[] encPubKey, byte[] msg32)
        {
            if (secKey32.Length != Constant.SECRET_KEY_SIZE)
                throw new ArgumentException($"{nameof(secKey32)} must be {Constant.SECRET_KEY_SIZE} bytes");

            if (encPubKey.Length != Constant.PUBLIC_KEY_SIZE)
                throw new ArgumentException($"{nameof(encPubKey)} must be {Constant.SECRET_KEY_SIZE} bytes");
            
            if (msg32.Length != Constant.MESSAGE_SIZE)
                throw new ArgumentException($"{nameof(msg32)} must be {Constant.MESSAGE_SIZE} bytes");
            
            var adaptorSig162 = new byte[162];
            return secp256k1_ecdsa_adaptor_encrypt(Context, adaptorSig162, secKey32, encPubKey, msg32, IntPtr.Zero, (IntPtr)null) == 1 ? adaptorSig162 : null;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="adaptorSig162"></param>
        /// <param name="pubKey"></param>
        /// <param name="msg32"></param>
        /// <param name="encPubKey"></param>
        /// <returns></returns>
        public bool Verify(byte[] adaptorSig162, byte[] pubKey, byte[] msg32, byte[] encPubKey)
        {
            if (adaptorSig162.Length != Constant.ADAPTOR_SIG_SIZE)
                throw new ArgumentException($"{nameof(adaptorSig162)} must be {Constant.ADAPTOR_SIG_SIZE} bytes");
            
            if (pubKey.Length != Constant.PUBLIC_KEY_SIZE)
                throw new ArgumentException($"{nameof(pubKey)} must be {Constant.PUBLIC_KEY_SIZE} bytes");
            
            if (msg32.Length != Constant.MESSAGE_SIZE)
                throw new ArgumentException($"{nameof(msg32)} must be {Constant.MESSAGE_SIZE} bytes");

            if (encPubKey.Length != Constant.PUBLIC_KEY_SIZE)
                throw new ArgumentException($"{nameof(encPubKey)} must be {Constant.PUBLIC_KEY_SIZE} bytes");
            
            return secp256k1_ecdsa_adaptor_verify(Context, adaptorSig162, pubKey, msg32, encPubKey) == 1;
        }
        
        /// <summary>
        /// 
        /// </summary>
        /// <param name="decKey"></param>
        /// <param name="adaptorSig162"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentException"></exception>
        public byte[]? Decrypt(byte[] decKey, byte[] adaptorSig162)
        {
            if (adaptorSig162.Length != Constant.ADAPTOR_SIG_SIZE)
                throw new ArgumentException($"{nameof(adaptorSig162)} must be {Constant.SIGNATURE_SIZE} bytes");
            
            if (decKey.Length != Constant.SECRET_KEY_SIZE)
                throw new ArgumentException($"{nameof(decKey)} must be {Constant.SECRET_KEY_SIZE} bytes");
            
            var sig = new byte[64];
            return secp256k1_ecdsa_adaptor_decrypt(Context, sig, decKey, adaptorSig162) == 1 ? sig : null;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="sig"></param>
        /// <param name="adaptorSig162"></param>
        /// <param name="encPubKey"></param>
        /// <returns></returns>
        public byte[]? Recover(byte[] sig, byte[] adaptorSig162, byte[] encPubKey)
        {
            if (sig.Length != Constant.SIGNATURE_SIZE)
                throw new ArgumentException($"{nameof(sig)} must be {Constant.SIGNATURE_SIZE} bytes");
            
            if (adaptorSig162.Length != Constant.ADAPTOR_SIG_SIZE)
                throw new ArgumentException($"{nameof(adaptorSig162)} must be {Constant.ADAPTOR_SIG_SIZE} bytes");

            if (encPubKey.Length != Constant.PUBLIC_KEY_SIZE)
                throw new ArgumentException($"{nameof(encPubKey)} must be {Constant.PUBLIC_KEY_SIZE} bytes");

            var decKey32 = new byte[32];
            return secp256k1_ecdsa_adaptor_recover(Context, decKey32, sig, adaptorSig162, encPubKey) == 1
                ? decKey32
                : null;
        }
        
        /// <summary>
        /// 
        /// </summary>
        public void Dispose()
        {
            if (Context == IntPtr.Zero) return;

            secp256k1_context_destroy(Context);
            Context = IntPtr.Zero;
        }
    }
}
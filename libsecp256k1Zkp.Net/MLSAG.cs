﻿using System;
using System.Runtime.InteropServices;

using static Libsecp256k1Zkp.Net.Secp256k1Native;
using static Libsecp256k1Zkp.Net.MlsagNative;

namespace Libsecp256k1Zkp.Net
{
    public class Transaction
    {
        public byte[]? Commitment { get; set; }
        public byte[]? PublicKey { get; set; }
    }

    public unsafe class MLSAG : IDisposable
    {
        public IntPtr Context { get; private set; }

        public MLSAG()
        {
            Context = secp256k1_context_create((uint)(Flags.SECP256K1_CONTEXT_SIGN | Flags.SECP256K1_CONTEXT_VERIFY));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="sk"></param>
        /// <param name="pk"></param>
        /// <returns></returns>
        public byte[]? ToKeyImage(byte[] sk, byte[] pk)
        {
            if (pk.Length < Constant.PUBLIC_KEY_COMPRESSED_SIZE)
                throw new ArgumentException($"{nameof(pk)} must be {Constant.PUBLIC_KEY_COMPRESSED_SIZE} bytes");

            if (sk.Length < Constant.BLIND_LENGTH)
                throw new ArgumentException($"{nameof(sk)} must be {Constant.BLIND_LENGTH} bytes");

            if (pk.Length > Constant.PUBLIC_KEY_SIZE)
                throw new ArgumentException($"{nameof(pk)} must be {Constant.PUBLIC_KEY_SIZE} bytes");

            if (pk.Length == Constant.PUBLIC_KEY_SIZE)
            {
                using var secp256K1 = new Secp256k1();
                pk = secp256K1.SerializePublicKey(pk, Flags.SECP256K1_EC_COMPRESSED);
            }

            byte[]? keyImage = null;

            if (pk.Length != Constant.PUBLIC_KEY_COMPRESSED_SIZE) return keyImage;

            keyImage = new byte[Constant.PUBLIC_KEY_COMPRESSED_SIZE];
            keyImage = secp256k1_get_keyimage(Context, keyImage, pk, sk) == 0 ? keyImage : null;

            return keyImage;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="publicKeys"></param>
        /// <param name="blindSumOut"></param>
        /// <param name="nOuts"></param>
        /// <param name="nBlinded"></param>
        /// <param name="nCols"></param>
        /// <param name="nRows"></param>
        /// <param name="inputs"></param>
        /// <param name="outputs"></param>
        /// <param name="blinds"></param>
        /// <returns></returns>
        public bool Prepare(Span<byte> publicKeys, Span<byte> blindSumOut, int nOuts, int nBlinded, int nCols, int nRows, Span<byte[]> inputs, Span<byte[]> outputs, Span<byte[]> blinds)
        {
            fixed (byte* publicKeysPtr = &MemoryMarshal.GetReference(publicKeys),
                blindSumOutPtr = &MemoryMarshal.GetReference(blindSumOut))
            {
                return secp256k1_prepare_mlsag(publicKeysPtr, blindSumOutPtr, nOuts, nBlinded, nCols, nRows,
                    Util.ToIntPtrs(inputs), Util.ToIntPtrs(outputs), Util.ToIntPtrs(blinds)) == 0;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="kiOut">byte[32]</param>
        /// <param name="pcOut">byte[33 * nRows + 1]</param>
        /// <param name="psOut">byte[nCols * nRows * 32]</param>
        /// <param name="nonce"></param>
        /// <param name="preimage"></param>
        /// <param name="nCols"></param>
        /// <param name="nRows"></param>
        /// <param name="index"></param>
        /// <param name="blinds"></param>
        /// <param name="publicKeys"></param>
        /// <returns></returns>
        public bool Generate(Span<byte> kiOut, Span<byte> pcOut, Span<byte> psOut, Span<byte> nonce, Span<byte> preimage, int nCols, int nRows, int index, Span<byte[]> blinds, Span<byte> publicKeys)
        {
            fixed (byte* kiOutPtr = &MemoryMarshal.GetReference(kiOut),
                pcOutPtr = &MemoryMarshal.GetReference(pcOut),
                psOutPtr = &MemoryMarshal.GetReference(psOut),
                noncePtr = &MemoryMarshal.GetReference(nonce),
                preimagePtr = &MemoryMarshal.GetReference(preimage),
                publicKeysPtr = &MemoryMarshal.GetReference(publicKeys))
            {

                return secp256k1_generate_mlsag(Context, kiOutPtr, pcOutPtr, psOutPtr,
                    noncePtr, preimagePtr, nCols, nRows, index, Util.ToIntPtrs(blinds), publicKeysPtr) == 0;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="preimage"></param>
        /// <param name="nCols"></param>
        /// <param name="nRows"></param>
        /// <param name="publicKeys"></param>
        /// <param name="ki"></param>
        /// <param name="pc"></param>
        /// <param name="ps"></param>
        /// <returns></returns>
        public bool Verify(Span<byte> preimage, int nCols, int nRows, Span<byte> publicKeys, Span<byte> ki, Span<byte> pc, Span<byte> ps)
        {
            fixed (byte* preimagePtr = &MemoryMarshal.GetReference(preimage),
                publicKeysPtr = &MemoryMarshal.GetReference(publicKeys),
                kiPtr = &MemoryMarshal.GetReference(ki),
                pcPtr = &MemoryMarshal.GetReference(pc),
                psPtr = &MemoryMarshal.GetReference(ps))
            {
                return secp256k1_verify_mlsag(Context, preimagePtr, nCols, nRows, publicKeysPtr, kiPtr, pcPtr, psPtr) == 0;
            }
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

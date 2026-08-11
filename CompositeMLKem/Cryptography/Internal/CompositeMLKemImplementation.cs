using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace Rotherprivat.Cryptography.Internal
{
    /// <exclude />
    internal class CompositeMLKemImplementation : CompositeMLKem
    {
        private MLKem? _MLKem = null;
        private ITraditionalKem? _TraditionalKem = null;

        internal static CompositeMLKem GenerateKeyImplementation(CompositeMLKemAlgorithm algorithm)
        {
            var traditionalKem = TraditionalKem.Create(algorithm);
            traditionalKem.GenerateKey();
            return new CompositeMLKemImplementation(algorithm)
            {
                _MLKem = MLKem.GenerateKey(algorithm.MLKemAlgorithm),
                _TraditionalKem = traditionalKem
            };
        }

        internal static CompositeMLKem ImportPrivateKeyImplementation(CompositeMLKemAlgorithm algorithm, ReadOnlySpan<byte> privateKey)
        {
            var mlKemSeed = privateKey[..algorithm.MLKemAlgorithm.PrivateSeedSizeInBytes];
            var mlKem = MLKem.ImportPrivateSeed(algorithm.MLKemAlgorithm, mlKemSeed);

            var traditionalPrivateKey = privateKey[algorithm.MLKemAlgorithm.PrivateSeedSizeInBytes..];
            var traditionalKem = TraditionalKem.Create(algorithm);
            traditionalKem.ImportPrivateKey(traditionalPrivateKey);

            return new CompositeMLKemImplementation(algorithm)
            {
                _MLKem = mlKem,
                _TraditionalKem = traditionalKem
            };
        }

        internal static CompositeMLKem ImportEncapsulationKeyImplementation(CompositeMLKemAlgorithm algorithm, ReadOnlySpan<byte> encapsulationKey)
        {
            var mlKemEncapsulationKey = encapsulationKey[..algorithm.MLKemAlgorithm.EncapsulationKeySizeInBytes];
            var traditionalPublicKey = encapsulationKey[algorithm.MLKemAlgorithm.EncapsulationKeySizeInBytes..];

            var traditionalKem = TraditionalKem.Create(algorithm);
            traditionalKem.ImportPublicKey(traditionalPublicKey);

            return new CompositeMLKemImplementation(algorithm)
            {
                _MLKem = MLKem.ImportEncapsulationKey(algorithm.MLKemAlgorithm, mlKemEncapsulationKey),
                _TraditionalKem = traditionalKem
            };
        }

        /// <summary>
        /// Hidden Constructor
        /// </summary>
        /// <param name="algorithm"></param>
        protected CompositeMLKemImplementation(CompositeMLKemAlgorithm algorithm)
        : base(algorithm)
        {
        }

        protected override byte[] ExportPrivateKeyImplementation()
        {
            EnsureValid();

            var k1 = _MLKem.ExportPrivateSeed();
            var k2 = _TraditionalKem.ExportPrivateKey();

            var key = new byte[k1.Length + k2.Length];
            Buffer.BlockCopy(k1, 0, key, 0, k1.Length);
            Buffer.BlockCopy(k2, 0, key, k1.Length, k2.Length);
            return key;

        }

        protected override byte[] ExportEncapsulationKeyImplementation()
        {
            EnsureValid();

            var k1 = _MLKem.ExportEncapsulationKey();
            var k2 = _TraditionalKem.ExportPublicKey();

            var key = new byte[k1.Length + k2.Length];
            Buffer.BlockCopy(k1, 0, key, 0, k1.Length);
            Buffer.BlockCopy(k2, 0, key, k1.Length, k2.Length);
            return key;
        }
        protected override void EncapsulateImplementation(Span<byte> ciphertext, Span<byte> sharedSecret)
        {
            EnsureValid();

            // append to ciphertext tradCT = public part of ephemeral key 
            var tradCT = ciphertext[Algorithm.MLKemAlgorithm.CiphertextSizeInBytes..];
            var tradPK = _TraditionalKem.ExportPublicKey();
            var tradSecret = _TraditionalKem.Encapsulate(tradCT);
            
            // ML-KEM get ciphertext and KL-KEM shared secret
            byte[] mlKemKey = new byte[Algorithm.MLKemAlgorithm.SharedSecretSizeInBytes];
            var p = ciphertext[..Algorithm.MLKemAlgorithm.CiphertextSizeInBytes];
            _MLKem.Encapsulate(p, mlKemKey);

            // combine ML-KEM- and traditional shared secret
            Combine(mlKemKey, tradSecret, tradCT.ToArray(), tradPK, Algorithm.Label).CopyTo(sharedSecret);
        }

        protected override void DecapsulateImplementation(ReadOnlySpan<byte> ciphertext, Span<byte> sharedSecret)
        {
            EnsureValid();

            // ML-KEM get  KL-KEM shared secret
            var mlKemCipherText = ciphertext[..Algorithm.MLKemAlgorithm.CiphertextSizeInBytes];
            var mlKemKey = new byte[Algorithm.MLKemAlgorithm.SharedSecretSizeInBytes];
            _MLKem.Decapsulate(mlKemCipherText, mlKemKey);

            var tradCT = ciphertext[Algorithm.MLKemAlgorithm.CiphertextSizeInBytes..].ToArray();
            var tradPK = _TraditionalKem.ExportPublicKey();
            var tradKey = _TraditionalKem.Decapsulate(tradCT);


            // combine ML-KEM- and traditional shared secret
            Combine(mlKemKey, tradKey,tradCT, tradPK, Algorithm.Label).CopyTo(sharedSecret);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _MLKem?.Dispose();
                _TraditionalKem?.Dispose();
            }
            _MLKem = null;
            base.Dispose(disposing);
        }


        [MemberNotNull(nameof(_MLKem), nameof(_TraditionalKem))]
        private void EnsureValid()
        {
            if (_MLKem == null || _TraditionalKem == null)
                throw new CryptographicException("Not initialized.");
        }

        private static byte[] Combine(byte[] mlkemKey, byte[] tradKey, byte[] tradCT, byte[] tradPK, byte[] label)
        {
            using var sha3 = SHA3_256.Create();
            sha3.TransformBlock(mlkemKey, 0, mlkemKey.Length, null, 0);
            sha3.TransformBlock(tradKey, 0, tradKey.Length, null, 0);
            sha3.TransformBlock(tradCT, 0, tradCT.Length, null, 0);
            sha3.TransformBlock(tradPK, 0, tradPK.Length, null, 0);
            sha3.TransformFinalBlock(label, 0, label.Length);

            return sha3.Hash ?? throw new CryptographicException("Failed to Combine Keys");
        }
    }
}

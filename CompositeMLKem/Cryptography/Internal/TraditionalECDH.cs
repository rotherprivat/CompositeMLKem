using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace Rotherprivat.Cryptography.Internal
{
    internal class TraditionalECDH : TraditionalKem
    {
        private ECDiffieHellman? _traditionalECDH = null;
 
        public override void GenerateKey()
        {
            if (Algorithm == null)
                throw new CryptographicException("Not initialized.");
            _traditionalECDH = ECDiffieHellman.Create(Algorithm.ECCurve);
        }

        public override void ImportPrivateKey(ReadOnlySpan<byte> traditionalPrivateKey)
        {
            if (Algorithm == null)
                throw new CryptographicException("Not initialized.");
            var ecdh = ECDiffieHellman.Create();
            ecdh.ImportECPrivateKey(traditionalPrivateKey, out _);
            _traditionalECDH = ecdh;
        }

        public override void ImportPublicKey(ReadOnlySpan<byte> traditionalPublicKey)
        {
            if (Algorithm == null)
                throw new CryptographicException("Not initialized.");
            var ecParams = ReadPublicECParameters(Algorithm, traditionalPublicKey);
            ecParams.Validate();
            _traditionalECDH = ECDiffieHellman.Create(ecParams);
        }

        public static ECParameters ReadPublicECParameters(CompositeMLKemAlgorithm algorithm, ReadOnlySpan<byte> tradPk)
        {
            if (tradPk[0] != 0x04)
                throw new CryptographicException("Invalid Ciphertext");

            var x = tradPk.Slice(1, algorithm.ECPointValueSizeInBytes);
            var y = tradPk.Slice(1 + algorithm.ECPointValueSizeInBytes, algorithm.ECPointValueSizeInBytes);

            return new ECParameters()
            {
                Curve = algorithm.ECCurve,
                D = null,
                Q = new ECPoint()
                {
                    X = x.ToArray(),
                    Y = y.ToArray()
                }
            };
        }

        public override byte[] ExportPublicKey()
        {
            EnsureValid();
            var param = _traditionalECDH.ExportParameters(false);
            return param.ExportECPublicKeyBytes();
        }

        public override byte[] Encapsulate(Span<byte> tradCT)
        {
            EnsureValid();
            using var ecEphemeralKey = ECDiffieHellman.Create(Algorithm.ECCurve);
            var ecKey = ecEphemeralKey.DeriveRawSecretAgreement(_traditionalECDH.PublicKey);
            var ecParam = ecEphemeralKey.ExportParameters(false);

            // append to ciphertext tradCT = public part of ephemeral key 
            tradCT[0] = 0x04;
            var p = tradCT.Slice(1, Algorithm.ECPointValueSizeInBytes);
            ecParam.Q.X.CopyTo(p);
            p = tradCT.Slice(Algorithm.ECPointValueSizeInBytes + 1, Algorithm.ECPointValueSizeInBytes);
            ecParam.Q.Y.CopyTo(p);

            return ecKey;
        }

        public override byte[] Decapsulate(Span<byte> tradCT)
        {
            EnsureValid();
            // get traditional ephemeral key from ciphertext
            var ecEphemeralParams = ReadPublicECParameters(Algorithm, tradCT);
            ecEphemeralParams.Validate();
            using var ecEphemeralKey = ECDiffieHellman.Create(ecEphemeralParams);

            // get traditional shared secret
            var tradKey = _traditionalECDH.DeriveRawSecretAgreement(ecEphemeralKey.PublicKey);

            return tradKey;
        }

        public override byte[] ExportPrivateKey()
        {
            EnsureValid();
            return _traditionalECDH.ExportECPrivateKeyD();
        }

        [MemberNotNull(nameof(_traditionalECDH))]
        protected override void EnsureValid()
        {
            base.EnsureValid();
            if (_traditionalECDH == null)
                throw new CryptographicException("Not initialized.");
        }
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (disposing)
            {
                _traditionalECDH?.Dispose();
            }
            _traditionalECDH = null;
        }

    }
}

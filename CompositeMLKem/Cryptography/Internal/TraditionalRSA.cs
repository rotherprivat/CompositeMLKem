using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace Rotherprivat.Cryptography.Internal
{
    internal class TraditionalRSA : TraditionalKem
    {
        private RSA? _traditionalRSA = null;

        public override void GenerateKey()
        {
            if (Algorithm == null)
                throw new CryptographicException("Not initialized.");
            _traditionalRSA = RSA.Create(Algorithm.RSAKeySize);
        }

        public override void ImportPrivateKey(ReadOnlySpan<byte> traditionalPrivateKey)
        {
            if (Algorithm == null)
                throw new CryptographicException("Not initialized.");

            var rsa = RSA.Create();
            rsa.ImportRSAPrivateKey(traditionalPrivateKey, out _);

            _traditionalRSA = rsa;
        }

        public override void ImportPublicKey(ReadOnlySpan<byte> traditionalPublicKey)
        {
            if (Algorithm == null)
                throw new CryptographicException("Not initialized.");

            var rsa = RSA.Create();
            rsa.ImportRSAPublicKey(traditionalPublicKey, out _);
            _traditionalRSA = rsa;
        }

        public override byte[] ExportPublicKey()
        {
            EnsureValid();
            return _traditionalRSA.ExportRSAPublicKey();
        }

        public override byte[] ExportPrivateKey()
        {
            EnsureValid();
            return _traditionalRSA.ExportRSAPrivateKey();
        }


        public override byte[] Decapsulate(Span<byte> tradCT)
        {
            EnsureValid();
            var key = _traditionalRSA.Decrypt(tradCT, RSAEncryptionPadding.OaepSHA256);
            if (key.Length != 32)
                throw new CryptographicException("Traditional shared key is invalid.");

            return key;
        }


        public override byte[] Encapsulate(Span<byte> tradCT)
        {
            EnsureValid();
            var tradKey = RandomNumberGenerator.GetBytes(32);
            _traditionalRSA.Encrypt(tradKey, tradCT, RSAEncryptionPadding.OaepSHA256);
            return tradKey;
        }

        [MemberNotNull(nameof(_traditionalRSA))]
        protected override void EnsureValid()
        {
            base.EnsureValid();

            if (_traditionalRSA == null)
                throw new CryptographicException("Not initialized.");
        }


        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (disposing)
            {
                _traditionalRSA?.Dispose();
            }
            _traditionalRSA = null;
        }
    }
}

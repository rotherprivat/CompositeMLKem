using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace Rotherprivat.Cryptography.Internal
{
    internal abstract class TraditionalKem : ITraditionalKem
    {
        private bool disposedValue;

        public CompositeMLKemAlgorithm? Algorithm { get ; set; }

        public static ITraditionalKem Create(CompositeMLKemAlgorithm algorithm)
        {
            if (algorithm.IsTraditionalECDH)
            {
                return new TraditionalECDH()
                {
                    Algorithm = algorithm
                };
            }
            else
            {
                return new TraditionalRSA()
                {
                    Algorithm = algorithm
                };
            }
        }

        public abstract byte[] Decapsulate(Span<byte> tradCT);

        public abstract byte[] Encapsulate(Span<byte> tradCT);

        public abstract byte[] ExportPrivateKey();

        public abstract byte[] ExportPublicKey();

        public abstract void GenerateKey();

        public abstract void ImportPrivateKey(ReadOnlySpan<byte> traditionalPrivateKey);

        public abstract void ImportPublicKey(ReadOnlySpan<byte> traditionalPublicKey);

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                disposedValue = true;
            }
            Algorithm = null;
        }

        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        [MemberNotNull(nameof(Algorithm))]
        protected virtual void EnsureValid()
        {
            if (Algorithm == null)
                throw new CryptographicException("Not initialized.");
        }

    }
}

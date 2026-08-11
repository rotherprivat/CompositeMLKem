namespace Rotherprivat.Cryptography.Internal
{
    internal interface ITraditionalKem: IDisposable
    {
        public CompositeMLKemAlgorithm? Algorithm { get; set; }
        abstract static ITraditionalKem Create(CompositeMLKemAlgorithm algorithm);
        public void GenerateKey();
        public void ImportPrivateKey(ReadOnlySpan<byte> traditionalPrivateKey);
        public void ImportPublicKey(ReadOnlySpan<byte> traditionalPublicKey);
        public byte[] Encapsulate(Span<byte> tradCT);
        public byte[] Decapsulate(Span<byte> tradCT);
        public byte[] ExportPublicKey();
        public byte[] ExportPrivateKey();
    }
}

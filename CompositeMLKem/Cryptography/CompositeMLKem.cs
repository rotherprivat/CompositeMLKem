using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using Rotherprivat.Cryptography.Internal;

// standards:
// doc: https://lamps-wg.github.io/draft-composite-kem/draft-ietf-lamps-pq-composite-kem.html
// git: https://github.com/lamps-wg/draft-composite-kem


namespace Rotherprivat.Cryptography
{
    /// <summary>
    /// <para>
    ///   Keys and algorithm implementation of the CompositeMLKem, a composed traditional and 
    ///   ML-KEM post quantum key exchange algorithm. The Interface and implementation is analog to the
    ///   System.Security.Cryptography.MLKem class of the .NET platform.
    /// </para>
    /// <para>
    ///   See IETF draft <a href="https://lamps-wg.github.io/draft-composite-kem/draft-ietf-lamps-pq-composite-kem.html">documentation</a>
    ///   and <a href="https://github.com/lamps-wg/draft-composite-kem">repository</a> on GitHub.
    /// </para>
    /// </summary>
    public abstract class CompositeMLKem : IDisposable
    {
        #region Properties
        /// <summary>
        /// Algorithm description
        /// </summary>
        public CompositeMLKemAlgorithm  Algorithm { get; }

        /// <summary>
        /// Indicates if the algorithm supported by the current platform
        /// </summary>
        public static bool IsSupported => MLKem.IsSupported;
        #endregion

        #region Public methods: Key handling
        /// <summary>
        /// Generate new keys for ML-KEM and traditional key exchange algorithms
        /// </summary>
        /// <param name="algorithm">Algorithm description</param>
        /// <returns>keys and algorithm implementation</returns>
        public static CompositeMLKem GenerateKey(CompositeMLKemAlgorithm algorithm)
        {
            return CompositeMLKemImplementation.GenerateKeyImplementation(algorithm);
        }

        /// <summary>
        /// Import private keys of ML-KEM and traditional key exchange algorithms
        /// </summary>
        /// <param name="algorithm">Algorithm description</param>
        /// <param name="privateKey">private key</param>
        /// <returns>keys and algorithm implementation</returns>
        public static CompositeMLKem ImportPrivateKey(CompositeMLKemAlgorithm algorithm, byte[] privateKey)
        {
            return CompositeMLKemImplementation.ImportPrivateKeyImplementation(algorithm, privateKey);
        }

        /// <summary>
        /// Import private keys of ML-KEM and traditional key exchange algorithms
        /// </summary>
        /// <param name="pkcs8">PKCS#8 encoded private key</param>
        /// <returns>keys and algorithm implementation</returns>
        /// <exception cref="CryptographicException"></exception>
        public static CompositeMLKem ImportPkcs8PrivateKey(byte[] pkcs8)
        {
            // Requires ReadOnlMemory<T>
            var pkcs8Info = Pkcs8PrivateKeyInfo.Decode(pkcs8, out _);
            var oid = (pkcs8Info?.AlgorithmId.Value) ?? 
                throw new CryptographicException("Failed to parse PKCS#8.");

            var algorithm = CompositeMLKemAlgorithm.FromOid(oid) ??
                throw new CryptographicException("Invalid algorithm ID.");

            var privateKey = pkcs8Info.PrivateKeyBytes;

            return CompositeMLKemImplementation.ImportPrivateKeyImplementation(algorithm, privateKey.Span);
        }

        /// <summary>
        /// Import private keys of ML-KEM and traditional key exchange algorithms
        /// </summary>
        /// <param name="pkcs8">PKCS#8 encoded private key</param>
        /// <returns>keys and algorithm implementation</returns>
        /// <exception cref="CryptographicException"></exception>
        public static CompositeMLKem ImportPkcs8PrivateKey(ReadOnlySpan<byte> pkcs8)
        {
            // Copy to Array ...
            return ImportPkcs8PrivateKey(pkcs8.ToArray());
        }

        /// <summary>
        /// Import private keys of ML-KEM and traditional key exchange algorithms
        /// </summary>
        /// <param name="passwordBytes">password</param>
        /// <param name="pkcs8">PKCS#8 encoded private key</param>
        /// <returns>keys and algorithm implementation</returns>
        /// <exception cref="CryptographicException"></exception>
        public static CompositeMLKem ImportEncryptedPkcs8PrivateKey(ReadOnlySpan<byte> passwordBytes, byte[] pkcs8)
        {
            var pkcs8Info = Pkcs8PrivateKeyInfo.DecryptAndDecode(passwordBytes, pkcs8, out _);
            var oid = (pkcs8Info?.AlgorithmId.Value) ??
                throw new CryptographicException("Failed to parse PKCS#8.");

            var algorithm = CompositeMLKemAlgorithm.FromOid(oid) ??
                throw new CryptographicException("Invalid algorithm ID.");

            var privateKey = pkcs8Info!.PrivateKeyBytes;

            return CompositeMLKemImplementation.ImportPrivateKeyImplementation(algorithm, privateKey.Span);
        }

        /// <summary>
        /// Import private keys of ML-KEM and traditional key exchange algorithms
        /// </summary>
        /// <param name="password">password</param>
        /// <param name="pkcs8">PKCS#8 encoded private key</param>
        /// <returns>keys and algorithm implementation</returns>
        /// <exception cref="CryptographicException"></exception>
        public static CompositeMLKem ImportEncryptedPkcs8PrivateKey(ReadOnlySpan<char> password, byte[] pkcs8)
        {
            var pkcs8Info = Pkcs8PrivateKeyInfo.DecryptAndDecode(password, pkcs8, out _);
            var oid = pkcs8Info?.AlgorithmId.Value ??
                throw new CryptographicException("Failed to parse PKCS#8.");

            var algorithm = CompositeMLKemAlgorithm.FromOid(oid) ??
                throw new CryptographicException("Invalid algorithm ID.");

            var privateKey = pkcs8Info!.PrivateKeyBytes;

            return CompositeMLKemImplementation.ImportPrivateKeyImplementation(algorithm, privateKey.Span);
        }

        /// <summary>
        /// Import private keys of ML-KEM and traditional key exchange algorithms
        /// </summary>
        /// <param name="password">password</param>
        /// <param name="pkcs8">PKCS#8 encoded private key</param>
        /// <returns>keys and algorithm implementation</returns>
        /// <exception cref="CryptographicException"></exception>
        public static CompositeMLKem ImportEncryptedPkcs8PrivateKey(string password, byte[] pkcs8)
        {
            var pkcs8Info = Pkcs8PrivateKeyInfo.DecryptAndDecode(password, pkcs8, out _);
            var oid = pkcs8Info?.AlgorithmId.Value??
                throw new CryptographicException("Failed to parse PKCS#8.");

            var algorithm = CompositeMLKemAlgorithm.FromOid(oid) ??
                throw new CryptographicException("Invalid algorithm ID.");

            var privateKey = pkcs8Info!.PrivateKeyBytes;

            return CompositeMLKemImplementation.ImportPrivateKeyImplementation(algorithm, privateKey.Span);
        }

        /// <summary>
        /// Import encapsulation keys of ML-KEM and traditional key exchange algorithms
        /// </summary>
        /// <param name="algorithm">Algorithm description</param>
        /// <param name="encapsulationKey">encapsulation- /public- key</param>
        /// <returns>keys and algorithm implementation</returns>
        public static CompositeMLKem ImportEncapsulationKey(CompositeMLKemAlgorithm algorithm, byte[] encapsulationKey)
        {
            return CompositeMLKemImplementation.ImportEncapsulationKeyImplementation(algorithm, encapsulationKey);
        }

        /// <summary>
        /// Import encapsulation keys of ML-KEM and traditional key exchange algorithms
        /// </summary>
        /// <param name="algorithm">Algorithm description</param>
        /// <param name="encapsulationKey">encapsulation- /public- key</param>
        /// <returns>keys and algorithm implementation</returns>
        public static CompositeMLKem ImportEncapsulationKey(CompositeMLKemAlgorithm algorithm, ReadOnlySpan<byte> encapsulationKey)
        {
            return CompositeMLKemImplementation.ImportEncapsulationKeyImplementation(algorithm, encapsulationKey);
        }

        /// <summary>
        /// Import encapsulation keys of ML-KEM and traditional key exchange algorithms
        /// </summary>
        /// <param name="publicKey">DER encoded encapsulation- /public- key</param>
        /// <returns>keys and algorithm implementation</returns>
        public static CompositeMLKem ImportSubjectPublicKeyInfo(byte[] publicKey)
        {
            var asn1 = new AsnReader(publicKey, AsnEncodingRules.DER);
            var asnPk = asn1.ReadSequence();
            var ObjectId = asnPk.ReadSequence();
            var oid = ObjectId.ReadObjectIdentifier();
            if (ObjectId.HasData)
                ObjectId.ReadNull();

            var publicKeyBytes = asnPk.ReadBitString(out _);

            var algorithm = CompositeMLKemAlgorithm.FromOid(oid) ??
                throw new CryptographicException("Invalid Algorithm");


            return CompositeMLKemImplementation.ImportEncapsulationKeyImplementation(algorithm, publicKeyBytes);
        }

        /// <summary>
        /// Import encapsulation keys of ML-KEM and traditional key exchange algorithms
        /// </summary>
        /// <param name="publicKey">DER encoded encapsulation- /public- key</param>
        /// <returns>keys and algorithm implementation</returns>
        public static CompositeMLKem ImportSubjectPublicKeyInfo(ReadOnlySpan<byte> publicKey)
        {
            // Copy to Array ...
            return ImportSubjectPublicKeyInfo(publicKey.ToArray());
        }

        /// <summary>
        /// Import encapsulation keys of ML-KEM and traditional key exchange algorithms
        /// </summary>
        /// <param name="pemKey">PEM encoded encapsulation- /public- key</param>
        /// <returns>keys and algorithm implementation</returns>
        public static CompositeMLKem ImportFromPem(string pemKey)
        {
            var pem = PemEncoding.Find(pemKey);
            var label = pemKey[pem.Label];
            if (label != PemLabels.PublicKey)
                throw new CryptographicException("Invalid PEM-Type");

            var base64Data = pemKey[pem.Base64Data];

            var derData = Convert.FromBase64String(base64Data);

            return ImportSubjectPublicKeyInfo(derData);
        }

        /// <summary>
        /// Import encapsulation keys of ML-KEM and traditional key exchange algorithms
        /// </summary>
        /// <param name="pemKey">PEM encoded encapsulation- /public- key</param>
        /// <returns>keys and algorithm implementation</returns>
        public static CompositeMLKem ImportFromPem(ReadOnlySpan<char> pemKey)
        {
            var pem = PemEncoding.Find(pemKey);
            var label = pemKey[pem.Label];
            if (label != PemLabels.PublicKey)
                throw new CryptographicException("Invalid PEM-Type");

            var base64Data = pemKey[pem.Base64Data].ToString();

            var derData = Convert.FromBase64String(base64Data);


            return ImportSubjectPublicKeyInfo(derData);
        }

        /// <summary>
        /// Export private keys of ML-KEM and traditional key exchange algorithms
        /// </summary>
        /// <returns>private key</returns>
        public byte[] ExportPrivateKey()
        {
            return ExportPrivateKeyImplementation();
        }

        /// <summary>
        /// Export private keys of ML-KEM and traditional key exchange algorithms
        /// </summary>
        /// <returns>PKCS#8 encoded private key</returns>
        public byte[] ExportPkcs8PrivateKey()
        {
            var privateKey = ExportPrivateKey();
            var pkcs8Info = new Pkcs8PrivateKeyInfo(new Oid(Algorithm.Oid), null, privateKey);
            return pkcs8Info.Encode();
        }

        /// <summary>
        /// Export private keys of ML-KEM and traditional key exchange algorithms
        /// </summary>
        /// <param name="passwordBytes">Password</param>
        /// <param name="pbeParameters">Password-based encryption (PBE) parameters</param>
        /// <returns>PKCS#8 encoded private key</returns>
        public byte[] ExportEncryptedPkcs8PrivateKey(ReadOnlySpan<byte> passwordBytes, PbeParameters pbeParameters)
        {
            var privateKey = ExportPrivateKey();
            var pkcs8Info = new Pkcs8PrivateKeyInfo(new Oid(Algorithm.Oid), null, privateKey);
            return pkcs8Info.Encrypt(passwordBytes, pbeParameters);
        }

        /// <summary>
        /// Export private keys of ML-KEM and traditional key exchange algorithms
        /// </summary>
        /// <param name="password">Password</param>
        /// <param name="pbeParameters">Password-based encryption (PBE) parameters</param>
        /// <returns>PKCS#8 encoded private key</returns>
        public byte[] ExportEncryptedPkcs8PrivateKey(ReadOnlySpan<char> password, PbeParameters pbeParameters)
        {
            var privateKey = ExportPrivateKey();
            var pkcs8Info = new Pkcs8PrivateKeyInfo(new Oid(Algorithm.Oid), null, privateKey);
            return pkcs8Info.Encrypt(password, pbeParameters);
        }

        /// <summary>
        /// Export private keys of ML-KEM and traditional key exchange algorithms
        /// </summary>
        /// <param name="password">Password</param>
        /// <param name="pbeParameters">Password-based encryption (PBE) parameters</param>
        /// <returns>PKCS#8 encoded private key</returns>
        public byte[] ExportEncryptedPkcs8PrivateKey(string password, PbeParameters pbeParameters)
        {
            var privateKey = ExportPrivateKey();
            var pkcs8Info = new Pkcs8PrivateKeyInfo(new Oid(Algorithm.Oid), null, privateKey);
            return pkcs8Info.Encrypt(password, pbeParameters);
        }

        /// <summary>
        /// Export encapsulation keys of ML-KEM and traditional key exchange algorithms
        /// </summary>
        /// <returns>Encapsulation- /public- key</returns>
        public byte[] ExportEncapsulationKey()
        {
            return ExportEncapsulationKeyImplementation();
        }


        /// <summary>
        /// Export encapsulation keys of ML-KEM and traditional key exchange algorithms
        /// </summary>
        /// <returns>DER encoded encapsulation- /public- key</returns>
        public byte[] ExportSubjectPublicKeyInfo()
        {
            return ExportSubjectPublicKeyInfoAsAsn().Encode();
        }

        /// <summary>
        /// Export encapsulation keys of ML-KEM and traditional key exchange algorithms
        /// </summary>
        /// <returns>PEM encoded encapsulation- /public- key</returns>
        public string ExportSubjectPublicKeyInfoPem()
        {
            var buffer = ExportSubjectPublicKeyInfo();
            return PemEncoding.WriteString(PemLabels.PublicKey, buffer);
        }
        #endregion

        #region Public methods: Encapsulate / Decapsulate
        /// <summary>
        /// Create combined ciphertext and shared secret
        /// </summary>
        /// <param name="ciphertext">Combined ciphertext</param>
        /// <param name="sharedSecret">Combined shared secret</param>
        public void Encapsulate(out byte[] ciphertext, out byte[] sharedSecret)
        {
            var cipherTextLen = Algorithm.IsTraditionalECDH ? Algorithm.ECPublicKeySizeInBytes : Algorithm.RSAKeySize / 8;
            cipherTextLen +=  Algorithm.MLKemAlgorithm.CiphertextSizeInBytes;

            ciphertext = new byte[cipherTextLen];
            sharedSecret = new byte[SHA3_256.HashSizeInBytes];

            Encapsulate(ciphertext, sharedSecret);
        }

        /// <summary>
        /// Create combined ciphertext and shared secret
        /// </summary>
        /// <param name="ciphertext">Combined ciphertext</param>
        /// <param name="sharedSecret">Combined shared secret</param>
        public void Encapsulate(Span<byte> ciphertext, Span<byte> sharedSecret)
        {
            EncapsulateImplementation(ciphertext, sharedSecret);
        }

        /// <summary>
        /// Decapsulate the shared secret from ciphertext
        /// </summary>
        /// <param name="ciphertext">Combined ciphertext</param>
        /// <returns>Combined shared secret</returns>
        public byte[] Decapsulate(byte[] ciphertext)
        {
            var sharedSecret = new byte[SHA3_256.HashSizeInBytes];
            Decapsulate(ciphertext, sharedSecret);
            return sharedSecret;
        }

        /// <summary>
        /// Decapsulate the shared key from combined ciphertext
        /// </summary>
        /// <param name="ciphertext">Combined ciphertext</param>
        /// <param name="sharedSecret">Combined shared secret</param>
        public void Decapsulate(ReadOnlySpan<byte> ciphertext, Span<byte> sharedSecret)
        {
            DecapsulateImplementation(ciphertext, sharedSecret);
        }
        #endregion

        #region Abstract methods overridden by implementation class
        /// <summary>
        /// Implementation of ExportPrivateKey logic in derived class
        /// </summary>
        /// <param name="privateKey"></param>
        /// <exclude/>
        protected abstract byte[] ExportPrivateKeyImplementation();

        /// <summary>
        /// Implementation of ExportEncapsulationKey logic in derived class
        /// </summary>
        /// <param name="keyBuffer"></param>
        /// <exclude/>
        protected abstract byte[] ExportEncapsulationKeyImplementation();

        /// <summary>
        /// Implementation of Encapsulate logic in derived class
        /// </summary>
        /// <param name="ciphertext"></param>
        /// <param name="sharedSecret"></param>
        /// <exclude/>
        protected abstract void EncapsulateImplementation(Span<byte> ciphertext, Span<byte> sharedSecret);

        /// <summary>
        /// Implementation of Decapsulate logic in derived class
        /// </summary>
        /// <param name="ciphertext"></param>
        /// <param name="sharedSecret"></param>
        /// <exclude/>
        protected abstract void DecapsulateImplementation(ReadOnlySpan<byte> ciphertext, Span<byte> sharedSecret);
        #endregion

        #region Hidden constructor
#pragma warning disable IDE0290
        /// <summary>
        /// Hidden constructor
        /// </summary>
        /// <param name="algorithm"></param>
        /// <exclude/>
        protected CompositeMLKem(CompositeMLKemAlgorithm algorithm)
        {
            Algorithm = algorithm;
        }
        #endregion

        #region Private implementation, types and fields
#pragma warning restore IDE0290
        private AsnWriter ExportSubjectPublicKeyInfoAsAsn()
        {
            byte[] keyBuffer = ExportEncapsulationKeyImplementation();

            var asn1 = new AsnWriter(AsnEncodingRules.DER);
            using (asn1.PushSequence())
            {
                //AlgorithmIdentifier
                using (asn1.PushSequence())
                {
                    asn1.WriteObjectIdentifier(Algorithm.Oid);
                    //                    asn1.WriteNull();
                }

                asn1.WriteBitString(keyBuffer);
            }

            return asn1;
        }
        #endregion

        #region IDisposable
        private bool disposedValue;

        /// <exclude/>
        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    // TODO: dispose managed state (managed objects)
                }

                // TODO: free unmanaged resources (unmanaged objects) and override finalizer
                // TODO: set large fields to null
                disposedValue = true;
            }
        }

        // // TODO: override finalizer only if 'Dispose(bool disposing)' has code to free unmanaged resources
        // ~CompositeMLKem()
        // {
        //     // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        //     Dispose(disposing: false);
        // }

        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
        #endregion
    }
}

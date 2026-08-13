using System.Security.Cryptography;
using System.Text;

namespace Rotherprivat.Cryptography
{
    // Algorithms specified by:
    // https://lamps-wg.github.io/draft-composite-kem/draft-ietf-lamps-pq-composite-kem.html
    // Only a subset is implemented here

    // MLKEM768-RSA2048-SHA3-256 OID: 1.3.6.1.5.5.7.6.55
    // MLKEM768-RSA3072-SHA3-256 OID: 1.3.6.1.5.5.7.6.56
    // MLKEM768-RSA4096-SHA3-256 OID: 1.3.6.1.5.5.7.6.57
    // MLKEM768-X25519-SHA3-256 OID: 1.3.6.1.5.5.7.6.58
    // MLKEM768-ECDH-P256-SHA3-256 OID: 1.3.6.1.5.5.7.6.59
    // MLKEM768-ECDH-P384-SHA3-256 OID: 1.3.6.1.5.5.7.6.60
    // MLKEM768-ECDH-brainpoolP256r1-SHA3-256 OID: 1.3.6.1.5.5.7.6.61
    // MLKEM1024-RSA3072-SHA3-256 OID: 1.3.6.1.5.5.7.6.62
    // MLKEM1024-ECDH-P384-SHA3-256 OID: 1.3.6.1.5.5.7.6.63
    // MLKEM1024-ECDH-brainpoolP384r1-SHA3-256 OID: 1.3.6.1.5.5.7.6.64
    // MLKEM1024-X448-SHA3-256 OID: 1.3.6.1.5.5.7.6.65
    // MLKEM1024-ECDH-P521-SHA3-256 OID: 1.3.6.1.5.5.7.6.66


    /// <summary>
    /// <para>
    ///   Definition of CompositeMLKem algorithms, a combination of traditional KEM- and Post Quantum ML-Kem Algorithm.
    /// </para>
    /// <para>
    ///   See: <a href="https://lamps-wg.github.io/draft-composite-kem/draft-ietf-lamps-pq-composite-kem.html">Composite ML-KEM for use in X.509 Public Key Infrastructure</a>
    /// </para>
    /// </summary>
    public sealed class CompositeMLKemAlgorithm
    {
        #region Difined algorithms
        // specified algorithms
        private static readonly CompositeMLKemAlgorithm[] _Algorithms =
        [
            new ("MLKEM768-ECDH-P256-SHA3-256", "MLKEM768-P256", "1.3.6.1.5.5.7.6.59", MLKemAlgorithm.MLKem768, ECCurve.NamedCurves.nistP256),
            new ("MLKEM768-ECDH-P384-SHA3-256", "MLKEM768-P384", "1.3.6.1.5.5.7.6.60", MLKemAlgorithm.MLKem768, ECCurve.NamedCurves.nistP384),
            new ("MLKEM768-ECDH-brainpoolP256r1-SHA3-256", "MLKEM768-BP256", "1.3.6.1.5.5.7.6.61", MLKemAlgorithm.MLKem768, ECCurve.NamedCurves.brainpoolP256r1),
            new ("MLKEM1024-ECDH-P384-SHA3-256", "MLKEM1024-P384", "1.3.6.1.5.5.7.6.63", MLKemAlgorithm.MLKem1024, ECCurve.NamedCurves.nistP384),
            new ("MLKEM1024-ECDH-brainpoolP384r1-SHA3-256", "MLKEM1024-BP384", "1.3.6.1.5.5.7.6.64", MLKemAlgorithm.MLKem1024, ECCurve.NamedCurves.brainpoolP384r1),
            new ("MLKEM1024-ECDH-P521-SHA3-256", "MLKEM1024-P521", "1.3.6.1.5.5.7.6.66", MLKemAlgorithm.MLKem1024, ECCurve.NamedCurves.nistP521),
            new ("MLKEM768-RSA2048-SHA3-256", "MLKEM768-RSAOAEP2048", "1.3.6.1.5.5.7.6.55", MLKemAlgorithm.MLKem768, rsaKeySize: 2048),
            new ("MLKEM768-RSA3072-SHA3-256", "MLKEM768-RSAOAEP3072", "1.3.6.1.5.5.7.6.56", MLKemAlgorithm.MLKem768, rsaKeySize: 3072),
            new ("MLKEM768-RSA4096-SHA3-256", "MLKEM768-RSAOAEP4096", "1.3.6.1.5.5.7.6.57", MLKemAlgorithm.MLKem768, rsaKeySize: 4096),
            new ("MLKEM1024-RSA3072-SHA3-256", "MLKEM1024-RSAOAEP3072", "1.3.6.1.5.5.7.6.62", MLKemAlgorithm.MLKem1024, rsaKeySize: 3072)
        ];
        #endregion

        #region Properties with named algorithms


        /// <summary>
        /// MLKEM768-RSA2048-SHA3-256
        /// </summary>
        public static CompositeMLKemAlgorithm KMKem768WithRSA2048Sha3 { get; } = _Algorithms[6];

        /// <summary>
        /// MLKEM768-RSA3072-SHA3-256
        /// </summary>
        public static CompositeMLKemAlgorithm KMKem768WithRSA3072Sha3 { get; } = _Algorithms[7];

        /// <summary>
        /// MLKEM768-RSA4096-SHA3-256
        /// </summary>
        public static CompositeMLKemAlgorithm KMKem768WithRSA4096Sha3 { get; } = _Algorithms[8];

        /// <summary>
        /// MLKEM768-ECDH-P256-SHA3-256
        /// </summary>
        public static CompositeMLKemAlgorithm KMKem768WithECDhP256Sha3 { get; } = _Algorithms[0];

        /// <summary>
        /// MLKEM768-ECDH-P384-SHA3-256
        /// </summary>
        public static CompositeMLKemAlgorithm KMKem768WithECDhP384Sha3 { get; } = _Algorithms[1];

        /// <summary>
        /// MLKEM768-ECDH-brainpoolP256r1-SHA3-256
        /// </summary>
        public static CompositeMLKemAlgorithm KMKem768WithECDhBrainpoolP384Sha3 { get; } = _Algorithms[2];

        /// <summary>
        /// MLKEM1024-RSA3072-SHA3-256
        /// </summary>
        public static CompositeMLKemAlgorithm KMKem1024WithRSA3072Sha3 { get; } = _Algorithms[9];

        /// <summary>
        /// MLKEM1024-ECDH-P384-SHA3-256
        /// </summary>
        public static CompositeMLKemAlgorithm KMKem1024WithECDhP384Sha3 { get; } = _Algorithms[3];


        /// <summary>
        /// MLKEM1024-ECDH-brainpoolP384r1-SHA3-256
        /// </summary>
        public static CompositeMLKemAlgorithm KMKem1024WithECDhBrainpoolP384Sha3 { get; } = _Algorithms[4];

        /// <summary>
        /// MLKEM1024-ECDH-P521-SHA3-256
        /// </summary>
        public static CompositeMLKemAlgorithm KMKem1024WithECDhP521Sha3 { get; } = _Algorithms[5];
        #endregion

        #region Public properies
        /// <summary>
        /// Algorithm Name
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// Algorithm OID
        /// </summary>
        public string Oid { get; }

        /// <summary>
        /// Uses traditional RSA
        /// </summary>
        public bool IsTraditionalRSA => RSAKeySize != 0;

        /// <summary>
        /// Uses traditional ECDH
        /// </summary>
        public bool IsTraditionalECDH => RSAKeySize == 0;

        /// <summary>
        /// Used ML-KEM algorithm
        /// </summary>
        public MLKemAlgorithm MLKemAlgorithm { get; }

        /// <summary>
        /// Used EC-Curve, if traditional algorithm is ECDH
        /// </summary>
        public ECCurve ECCurve { get; }

        /// <summary>
        /// RSA keysize, if traditional algorithm is RSA
        /// </summary>
        public int RSAKeySize { get; }

        #endregion

        #region Public methods and overrides
        /// <summary>
        /// Get algorithm definition from OID
        /// </summary>
        /// <param name="oid"><see cref="Oid">Algorithm OID</see></param>
        /// <returns>Algorithm definition or null, if the oid can not be resolved</returns>
        public static CompositeMLKemAlgorithm? FromOid(string oid) => _Algorithms.FirstOrDefault(x => x.Oid == oid);

        public override int GetHashCode() => Name.GetHashCode();

        public override string ToString() => Name;
        #endregion

        #region Internal and private propertiies
        internal byte[] Label { get; }

        internal int ECPointValueSizeInBytes => ECCurve.Oid.FriendlyName switch
        {
            "nistP256" => 32,
            "brainpoolP256r1" => 32,
            "nistP384" => 48,
            "brainpoolP384r1" => 48,
            "nistP521" => 66,
            _ => throw new CryptographicException("Invalid EC-Curve")
        };

        internal int ECPublicKeySizeInBytes => 2 * ECPointValueSizeInBytes + 1;

        internal int ECPrivateKeyDSizeInBytes => ECCurve.Oid.FriendlyName switch
        {
            "nistP256" => 51,
            "brainpoolP256r1" => 52,
            "nistP384" => 64,
            "brainpoolP384r1" => 68,
            "nistP521" => 82,
            _ => throw new CryptographicException("Invalid EC-Curve")
        };
        #endregion

        #region Hidden constructor
        private CompositeMLKemAlgorithm(string name, string label, string oid, MLKemAlgorithm mLKemAlgorithm, ECCurve eCCurve)
        {
            Name = name;
            Label = Encoding.ASCII.GetBytes(label);
            Oid = oid;
            MLKemAlgorithm = mLKemAlgorithm;
            ECCurve = eCCurve;
        }


        private CompositeMLKemAlgorithm(string name, string label, string oid, MLKemAlgorithm mLKemAlgorithm, int rsaKeySize)
        {
            Name = name;
            Label = Encoding.ASCII.GetBytes(label);
            Oid = oid;
            MLKemAlgorithm = mLKemAlgorithm;
            RSAKeySize = rsaKeySize;
        }
        #endregion
    }
}

using Rotherprivat.Cryptography;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;

namespace Rotherprivat.CompositeMLKemTest
{
    internal class PrivateKeyComparer(CompositeMLKemAlgorithm algorithm) : IEqualityComparer<byte[]>
    {
        public static byte[] GetDkFromPkcs8(CompositeMLKemAlgorithm algorithm, byte[] pkcs8)
        {
            var pkcs8Info = Pkcs8PrivateKeyInfo.Decode(pkcs8, out _);
            var oid = (pkcs8Info?.AlgorithmId.Value) ??
                throw new CryptographicException("Failed to parse PKCS#8.");

            if (!string.Equals(algorithm.Oid, oid, StringComparison.InvariantCultureIgnoreCase))
                throw new CryptographicException("Invalid algorithm ID.");

            return pkcs8Info!.PrivateKeyBytes.ToArray();
        }

        public bool Equals(byte[]? x, byte[]? y)
        {
            ArgumentNullException.ThrowIfNull(x);
            ArgumentNullException.ThrowIfNull(y);

            if (_Algorithm.IsTraditionalECDH)
                return x.SequenceEqual(y);
            else
            {
                var mlKemX = x[.._Algorithm.MLKemAlgorithm.PrivateSeedSizeInBytes];
                var mlKemY = y[.._Algorithm.MLKemAlgorithm.PrivateSeedSizeInBytes];

                if (!mlKemX.SequenceEqual(mlKemY))
                    return false;

                var rsaX = x[_Algorithm.MLKemAlgorithm.PrivateSeedSizeInBytes..];
                var rsaY = y[_Algorithm.MLKemAlgorithm.PrivateSeedSizeInBytes..];

                var paramX = GetRsaParams(rsaX);
                var paramY = GetRsaParams(rsaY);

                return IsEqualRsaParams(paramX, paramY);
            }
        }

        private static  RSAParameters GetRsaParams(byte[] rsaBytes)
        {
            using var rsa = RSA.Create();
            rsa.ImportRSAPrivateKey(rsaBytes, out _);
            return rsa.ExportParameters(true);
        }

        private static bool ByteArrayEqual(byte[]? a, byte[]? b)
        {
            if (a is null || b is null) return false;
            return a.SequenceEqual(b);
        }

        private static bool IsEqualRsaParams(RSAParameters p1, RSAParameters p2)
        {
            if (!ByteArrayEqual(p1.Modulus, p2.Modulus)) return false;
            if (!ByteArrayEqual(p1.Exponent, p2.Exponent)) return false;
            if (!ByteArrayEqual(p1.P, p2.P)) return false;
            if (!ByteArrayEqual(p1.Q, p2.Q)) return false;
            if (!ByteArrayEqual(p1.DP, p2.DP)) return false;
            if (!ByteArrayEqual(p1.DQ, p2.DQ)) return false;
            if (!ByteArrayEqual(p1.InverseQ, p2.InverseQ)) return false;


            // D may be different see:
            // https://stackoverflow.com/questions/67588396/d-parameter-of-rsa-change-depending-on-how-you-access-the-private-key-of-a-certi            Assert.IsTrue(refPkcs8.SequenceEqual(rawPkcs8), $"Test vector {testData.tcId} compare dk_pkcs8 from DK failed");

            return true;
        }
        public int GetHashCode([DisallowNull] byte[] obj)
        {
            return Convert.ToBase64String(obj).GetHashCode();
        }

        private readonly CompositeMLKemAlgorithm _Algorithm = algorithm;
    }
}

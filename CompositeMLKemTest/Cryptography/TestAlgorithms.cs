using Rotherprivat.Cryptography;
using System.Security.Cryptography;

namespace Rotherprivat.CompositeMLKemTest.Cryptography
{
    public static class TestAlgorithms
    {
        public static IEnumerable<object[]> MlKemAlgorithms
        {
            get
            {
                return
                [
                    [MLKemAlgorithm.MLKem512],
                    [MLKemAlgorithm.MLKem768],
                    [MLKemAlgorithm.MLKem1024]
                ];
            }
        }
        public static IEnumerable<object[]> CompositeMlKemAlgorithms
        {
            get
            {
                return
                [
                    [CompositeMLKemAlgorithm.KMKem768WithRSA2048Sha3],
                    [CompositeMLKemAlgorithm.KMKem768WithRSA3072Sha3],
                    [CompositeMLKemAlgorithm.KMKem768WithRSA4096Sha3],
                    [CompositeMLKemAlgorithm.KMKem768WithECDhP256Sha3],
                    [CompositeMLKemAlgorithm.KMKem768WithECDhBrainpoolP384Sha3],
                    [CompositeMLKemAlgorithm.KMKem768WithECDhP384Sha3],
                    [CompositeMLKemAlgorithm.KMKem1024WithRSA3072Sha3],
                    [CompositeMLKemAlgorithm.KMKem1024WithECDhP384Sha3],
                    [CompositeMLKemAlgorithm.KMKem1024WithECDhBrainpoolP384Sha3],
                    [CompositeMLKemAlgorithm.KMKem1024WithECDhP521Sha3]
                ];
            }
        }

    }
}

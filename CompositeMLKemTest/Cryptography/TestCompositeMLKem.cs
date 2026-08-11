using Rotherprivat.Cryptography;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace Rotherprivat.CompositeMLKemTest.Cryptography
{
    [TestClass]
    public sealed class TestCompositeMLKem
    {
        private TestVector? _TestVector;
        private static IEnumerable<object[]> CompositeMlKemAlgorithms => TestAlgorithms.CompositeMlKemAlgorithms;

        [TestInitialize]
        public void Init()
        {
            var strTestVector = File.ReadAllText(@"./Cryptography/testvectors.json");
            _TestVector = JsonSerializer.Deserialize<TestVector>( strTestVector );
        }

        [TestMethod]
        public void _00_IsSupported()
        {
            Assert.IsTrue(CompositeMLKem.IsSupported, "PQC-Algorithms not supported by your platform.");
        }


        [TestMethod]
        [DynamicData(nameof(CompositeMlKemAlgorithms))]
        public void _01_DecapsulateByTestVectors(CompositeMLKemAlgorithm algorithm)
        {
            if (null == _TestVector)
                throw new InvalidOperationException("NoTestData");

            string id = "id-" + algorithm.Name;
            var testData = _TestVector.tests[id] ??
                throw new InvalidOperationException("requested TestData missing");

            var privateKey = Convert.FromBase64String(testData.dk);
            var cyphertext = Convert.FromBase64String(testData.c);
            var key = Convert.FromBase64String(testData.k);

            using var compositeMLKem = CompositeMLKem.ImportPrivateKey(algorithm, privateKey);

            var decapsulatedKey = compositeMLKem.Decapsulate(cyphertext);
            Assert.IsTrue(key.SequenceEqual(decapsulatedKey), $"Test vector {testData.tcId} compare shared key failed");
        }

        [TestMethod]
        [DynamicData(nameof(CompositeMlKemAlgorithms))]
        public void _02_ExportPkcs8PrivateKeyByTestVectors(CompositeMLKemAlgorithm algorithm)
        {
            if (null == _TestVector)
                throw new InvalidOperationException("NoTestData");

            string id = "id-" + algorithm.Name;
            var testData = _TestVector.tests[id] ??
                throw new InvalidOperationException("requested TestData missing");

            var refDk = Convert.FromBase64String(testData.dk);
            var refPkcs8 = Convert.FromBase64String(testData.dk_pkcs8);

            using var compositeMLKem = CompositeMLKem.ImportPrivateKey(algorithm, refDk);
            var rawPkcs8 = compositeMLKem.ExportPkcs8PrivateKey();

            if (algorithm.IsTraditionalECDH)
            {
                Assert.AreSequenceEqual(refPkcs8, rawPkcs8, $"Test vector {testData.tcId} compare exported PKCS#8 failed");
            }
            else
            {
                // extract native private key from PKCS#8
                // https://stackoverflow.com/questions/67588396/d-parameter-of-rsa-change-depending-on-how-you-access-the-private-key-of-a-certi            Assert.IsTrue(refPkcs8.SequenceEqual(rawPkcs8), $"Test vector {testData.tcId} compare dk_pkcs8 from DK failed");
                var dk = PrivateKeyComparer.GetDkFromPkcs8(algorithm, rawPkcs8);
                var refDkConverted = PrivateKeyComparer.GetDkFromPkcs8(algorithm, refPkcs8);
#pragma warning disable MSTEST0065
                Assert.AreEqual(refDkConverted, dk, new PrivateKeyComparer(algorithm), $"Test vector {testData.tcId} compare exported PKCS#8 failed");
#pragma warning restore MSTEST0065
            }
        }

        [TestMethod]
        [DynamicData(nameof(CompositeMlKemAlgorithms))]
        public void _03_ImportPkcs8PrivateKeyByTestVectors(CompositeMLKemAlgorithm algorithm)
        {
            if (null == _TestVector)
                throw new InvalidOperationException("NoTestData");

            string id = "id-" + algorithm.Name;
            var testData = _TestVector.tests[id] ??
                throw new InvalidOperationException("requested TestData missing");

            var refDk = Convert.FromBase64String(testData.dk);
            var pkcs8 = Convert.FromBase64String(testData.dk_pkcs8);

            using var compositeMLKem = CompositeMLKem.ImportPkcs8PrivateKey(pkcs8);
            var rawDk = compositeMLKem.ExportPrivateKey();

            // No different handling for ECDH and RSA
#pragma warning disable MSTEST0065
            Assert.AreEqual(refDk, rawDk, new PrivateKeyComparer(algorithm), $"Test vector {testData.tcId} compare DK from PKCS#8 failed");
#pragma warning restore MSTEST0065
        }

        [TestMethod]
        [DynamicData(nameof(CompositeMlKemAlgorithms))]
        public void _04_ExportEncapsulationKeyByVectors(CompositeMLKemAlgorithm algorithm)
        {
            if (null == _TestVector)
                throw new InvalidOperationException("NoTestData");

            string id = "id-" + algorithm.Name;
            var testData = _TestVector.tests[id] ??
                throw new InvalidOperationException("requested TestData missing");

            var privateKey = Convert.FromBase64String(testData.dk);
            var refEk = Convert.FromBase64String(testData.ek);

            using var compositeMLKem = CompositeMLKem.ImportPrivateKey(algorithm, privateKey);
            var rawEk = compositeMLKem.ExportEncapsulationKey();

            Assert.IsTrue(refEk.SequenceEqual(rawEk), $"Test vector {testData.tcId} compare EK from DK failed");

            // Get DER encoded public key from certificate in in test vector.
            using var refCer = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(testData.x5c));
            var refDerEk = refCer.ExportSubjectPublicKeyInfo();

            var derEk = compositeMLKem.ExportSubjectPublicKeyInfo();

            Assert.IsTrue(refDerEk.SequenceEqual(derEk), $"Test vector {testData.tcId} compare derEK from DK failed");

            string pemEk = compositeMLKem.ExportSubjectPublicKeyInfoPem();
            var pem = PemEncoding.Find(pemEk);
            string label = pemEk[pem.Label];
            string base64data = pemEk[pem.Base64Data];

            var derEkFromPem = Convert.FromBase64String(base64data);
            Assert.AreEqual("PUBLIC KEY", label, $"Test vector {testData.tcId} unexpected PEM Label");
            Assert.IsTrue(refDerEk.SequenceEqual(derEkFromPem), $"Test vector {testData.tcId} compare derEK from DK failed");
        }

        [TestMethod]
        [DynamicData(nameof(CompositeMlKemAlgorithms))]
        public void _05_EncapsulateVectors(CompositeMLKemAlgorithm algorithm)
        {
            if (null == _TestVector)
                throw new InvalidOperationException("NoTestData");

            string id = "id-" + algorithm.Name;
            var testData = _TestVector.tests[id] ??
                throw new InvalidOperationException("requested TestData missing");

            var privateKey = Convert.FromBase64String(testData.dk);
            var encapsulationKey = Convert.FromBase64String(testData.ek);

            using var bob = CompositeMLKem.ImportEncapsulationKey(algorithm, encapsulationKey);
            Assert.IsNotNull(bob, $"Test vector {testData.tcId} import ImportEncapsulationKey failed.");
            
            bob.Encapsulate(out var ciphertext, out var bobsSecret);

            // Encapsulate generates random different results on every call, so it can not be
            // validated by the test vectors. But we make sure that it works with the keys from the test vectors.

            using var alice = CompositeMLKem.ImportPrivateKey(algorithm, privateKey);
            Assert.IsNotNull(alice, $"Test vector {testData.tcId} import ImportPrivateKey failed.");

            var aliceSecret = alice.Decapsulate(ciphertext);
            Assert.IsTrue(bobsSecret.SequenceEqual(aliceSecret), "Key exchange failed, the shared keys are different");
        }

        [TestMethod]
        [DynamicData(nameof(CompositeMlKemAlgorithms))]
        public void _06_RoundtripExchangeKeyPkcs8Der(CompositeMLKemAlgorithm algorithm)
        {
            using var keyMaterial = CompositeMLKem.GenerateKey(algorithm);

            var derPublicKey = keyMaterial.ExportSubjectPublicKeyInfo();
            var pkcs8Key = keyMaterial.ExportPkcs8PrivateKey();

            using var alice = CompositeMLKem.ImportPkcs8PrivateKey(pkcs8Key);
            using var bob = CompositeMLKem.ImportSubjectPublicKeyInfo(derPublicKey);

            bob.Encapsulate(out var ciphertext, out var bobsSecret);

            var aliceSecret = alice.Decapsulate(ciphertext);

            Assert.IsTrue(bobsSecret.SequenceEqual(aliceSecret), "Key exchange failed, the shared keys are different");
        }

        [TestMethod]
        [DynamicData(nameof(CompositeMlKemAlgorithms))]
        public void _07_RoundtripExchangeKeyPkcs8EncryptedPem(CompositeMLKemAlgorithm algorithm)
        {
            using var keyMaterial = CompositeMLKem.GenerateKey(algorithm);


            // PEM uses DER and plain public Key
            var derPublicKey = keyMaterial.ExportSubjectPublicKeyInfoPem();
            var pkcs8Key = keyMaterial.ExportEncryptedPkcs8PrivateKey("secret", new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 210000));

            using var alice = CompositeMLKem.ImportEncryptedPkcs8PrivateKey("secret", pkcs8Key);
            using var bob = CompositeMLKem.ImportFromPem(derPublicKey);

            bob.Encapsulate(out var ciphertext, out var bobsSecret);

            var aliceSecret = alice.Decapsulate(ciphertext);

            Assert.IsTrue(bobsSecret.SequenceEqual(aliceSecret), "Key exchange failed, the shared keys are different");
        }
    }
}

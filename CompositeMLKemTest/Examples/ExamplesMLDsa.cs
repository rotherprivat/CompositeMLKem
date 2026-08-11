using System.Security.Cryptography;
using System.Text;

namespace Rotherprivat.KemBasedNetTest.Examples
{
    [TestClass]
    public sealed class ExamplesMLDsa
    {
        [TestMethod]
        public void MLDsaSignVerifyOriginal()
        {
            var message = "The quick brown fox jumps over the lazy dog.";

#pragma warning disable SYSLIB5006
            // Generate Keys, usually some kind of persistent keys are used for signing and validating
            byte[] mlDsaPkcs8PrivateKey;
            byte[] mlDsaPublicKeyInfo;

            using (var mlDsaKey = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa87))
            {
                mlDsaPkcs8PrivateKey = mlDsaKey.ExportPkcs8PrivateKey();
                mlDsaPublicKeyInfo = mlDsaKey.ExportSubjectPublicKeyInfo();
            }

            // Import private key e.g. from a persistent store
            using var alice = MLDsa.ImportPkcs8PrivateKey(mlDsaPkcs8PrivateKey);
            var signature = alice.SignData(Encoding.UTF8.GetBytes(message));

            // Import public key e.g. from a persistent store
            using var bob = MLDsa.ImportSubjectPublicKeyInfo(mlDsaPublicKeyInfo);
#pragma warning restore SYSLIB5006

            // Verify message by public key
            var isValid = bob.VerifyData(Encoding.UTF8.GetBytes(message), signature);

            Assert.IsTrue(isValid, "Verify original message = false, (expected true)");
        }

        [TestMethod]
        public void MLDsaSignVerifyTamperedWith()
        {
            var message = "The quick brown fox jumps over the lazy dog.";

#pragma warning disable SYSLIB5006
            // Generate Keys, usually some kind of persistent keys are used for signing and validating
            byte[] mlDsaPkcs8PrivateKey;
            byte[] mlDsaPublicKeyInfo;

            using (var mlDsaKey = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa87))
            {
                mlDsaPkcs8PrivateKey = mlDsaKey.ExportPkcs8PrivateKey();
                mlDsaPublicKeyInfo = mlDsaKey.ExportSubjectPublicKeyInfo();
            }

            // Import private key e.g. from a persistent store
            using var alice = MLDsa.ImportPkcs8PrivateKey(mlDsaPkcs8PrivateKey);
            var signature = alice.SignData(Encoding.UTF8.GetBytes(message));

            // Import public key e.g. from a persistent store
            using var bob = MLDsa.ImportSubjectPublicKeyInfo(mlDsaPublicKeyInfo);
#pragma warning restore SYSLIB5006

            // Tampering with the message
            message = message.Replace("brown", "brOwn");

            // Verify message by public key
            var isValid = bob.VerifyData(Encoding.UTF8.GetBytes(message), signature);

            Assert.IsFalse(isValid, "Verify tampered with message = true, (expected false)");
        }
    }
}

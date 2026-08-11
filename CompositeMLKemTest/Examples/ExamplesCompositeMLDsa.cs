using System.Security.Cryptography;
using System.Text;

namespace Rotherprivat.KemBasedNetTest.Examples
{
    [TestClass]
    public sealed class ExamplesCompositeMLDsa
    {
        [TestMethod]
        public void CompositeMLDsaSignVerifyOriginal()
        {
            var message = "The quick brown fox jumps over the lazy dog.";

#pragma warning disable SYSLIB5006

            // Generate Keys, usually some kind of persistent keys are used for signing and validating
            byte[] mlDsaPkcs8PrivateKey;
            byte[] mlDsaPublicKeyInfo;

            using (var mlDsaKey = CompositeMLDsa.GenerateKey(CompositeMLDsaAlgorithm.MLDsa87WithECDsaP521))
            {
                mlDsaPkcs8PrivateKey = mlDsaKey.ExportPkcs8PrivateKey();
                mlDsaPublicKeyInfo = mlDsaKey.ExportSubjectPublicKeyInfo();
            }

            // Import private key e.g. from a persistent store
            using var alice = CompositeMLDsa.ImportPkcs8PrivateKey(mlDsaPkcs8PrivateKey);
            var signature = alice.SignData(Encoding.UTF8.GetBytes(message));

            // Import public key e.g. from a persistent store
            using var bob = CompositeMLDsa.ImportSubjectPublicKeyInfo(mlDsaPublicKeyInfo);
#pragma warning restore SYSLIB5006

            // Verify message by public key
            var isValid = bob.VerifyData(Encoding.UTF8.GetBytes(message), signature);

            Assert.IsTrue(isValid, "Verify original message = false, (expected true)");
        }

        [TestMethod]
        public void CompositeMLDsaSignVerifyTamperedWith()
        {
            var message = "The quick brown fox jumps over the lazy dog.";

#pragma warning disable SYSLIB5006

            // Generate Keys, usually some kind of persistent keys are used for signing and validating
            byte[] mlDsaPkcs8PrivateKey;
            byte[] mlDsaPublicKeyInfo;

            using (var mlDsaKey = CompositeMLDsa.GenerateKey(CompositeMLDsaAlgorithm.MLDsa87WithECDsaP521))
            {
                mlDsaPkcs8PrivateKey = mlDsaKey.ExportPkcs8PrivateKey();
                mlDsaPublicKeyInfo = mlDsaKey.ExportSubjectPublicKeyInfo();
            }

            // Import private key e.g. from a persistent store
            using var alice = CompositeMLDsa.ImportPkcs8PrivateKey(mlDsaPkcs8PrivateKey);
            var signature = alice.SignData(Encoding.UTF8.GetBytes(message));

            // Import public key e.g. from a persistent store
            using var bob = CompositeMLDsa.ImportSubjectPublicKeyInfo(mlDsaPublicKeyInfo);
#pragma warning restore SYSLIB5006

            // Tampering with the message
            message = message.Replace("brown", "brOwn");

            // Verify message by public key
            var isValid = bob.VerifyData(Encoding.UTF8.GetBytes(message), signature);

            Assert.IsFalse(isValid, "Verify tampered with message = true, (expected false)");
        }
    }
}

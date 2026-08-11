using Rotherprivat.Cryptography;
using System.Text;

namespace Rotherprivat.KemBasedNetTest.Examples
{
    [TestClass]
    public sealed class TestReadmeExamples
    {
        [TestMethod]
        public void CompositeMLKemExample()
        {
            // Generate the key material
            var algorithm = CompositeMLKemAlgorithm.KMKem1024WithECDhP521Sha3;
            using var alice = CompositeMLKem.GenerateKey(algorithm);

            var derPublicKey = alice.ExportSubjectPublicKeyInfo();

            // Forward derPublicKey to Bob
            using var bob = CompositeMLKem.ImportSubjectPublicKeyInfo(derPublicKey);

            bob.Encapsulate(out var ciphertext, out var bobsSecret);
            // Bob will use bobsSecret

            // Forward ciphertext to Alice
            var aliceSecret = alice.Decapsulate(ciphertext);
            // Alice will use aliceSecret

            // Verify secrets
            Assert.IsTrue(bobsSecret.SequenceEqual(aliceSecret), "Key exchange failed, the shared secrets are different");
        }
    }
}

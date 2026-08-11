using System.Security.Cryptography;

namespace Rotherprivat.KemBasedNetTest.Examples
{
    [TestClass]
    public sealed class ExamplesMLKem
    {
        [TestMethod]
        public void MLKemExchangeKey_temp()
        {            
            // Alice: Generate private- and public-key
            using var alice = MLKem.GenerateKey(MLKemAlgorithm.MLKem1024);
#pragma warning disable SYSLIB5006
            // Alice: Send public key to bob
            var pubKey = alice.ExportSubjectPublicKeyInfo();

            // Bob: Import public key
            using var bob = MLKem.ImportSubjectPublicKeyInfo(pubKey);
#pragma warning restore SYSLIB5006

            // Bob: encapsulate and get shared key 
            // Bob: send ciphertext to alice
            bob.Encapsulate(out byte[] ciphertext, out byte[] bobsSharedKey);

            // Alice: Decapsulate ciphertext and get shared key
            byte[] aliceSharedKey = alice.Decapsulate(ciphertext);

            // Validate keys
            Assert.IsTrue(aliceSharedKey.SequenceEqual(bobsSharedKey), "Key exchange failed, the shared keys are different");
        }

        [TestMethod]
        public void MLKemExchangeKey_persistent()
        {
            byte[] persistentPrivateKey;

#pragma warning disable SYSLIB5006
            using (var key = MLKem.GenerateKey(MLKemAlgorithm.MLKem1024))
            {
                persistentPrivateKey = key.ExportPkcs8PrivateKey();
            }

            // Alice: Import private key e.g. from a persistent store
            using var alice = MLKem.ImportPkcs8PrivateKey(persistentPrivateKey);

            // Alice: Send public key to bob
            var pubKey = alice.ExportSubjectPublicKeyInfo();

            // Bob: Import public key
            using var bob = MLKem.ImportSubjectPublicKeyInfo(pubKey);
#pragma warning restore SYSLIB5006

            // Bob: encapsulate and get shared key 
            // Bob: send ciphertext to alice
            bob.Encapsulate(out byte[] ciphertext, out byte[] bobsSharedKey);

            // Alice: Decapsulate ciphertext and get shared key
            byte[] aliceSharedKey = alice.Decapsulate(ciphertext);

            // Validate keys
            Assert.IsTrue(aliceSharedKey.SequenceEqual(bobsSharedKey), "Key exchange failed, the shared keys are different");
        }

    }
}

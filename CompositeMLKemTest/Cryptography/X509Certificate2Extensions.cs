using System.Security.Cryptography.X509Certificates;
using System.Formats.Asn1;

namespace Rotherprivat.CompositeMLKemTest.Cryptography
{
    internal static class X509Certificate2Extensions
    {
        internal static byte[] ExportSubjectPublicKeyInfo(this X509Certificate2 cer)
        {
#if NET10_0_OR_GREATER
            return cer.PublicKey.ExportSubjectPublicKeyInfo();
#else
            byte[] certBytes = cer.RawData;
            
            //This is a workaround of a bug in .NET versions before V10.0 
            // https://github.com/dotnet/runtime/issues/110715
            //
            // Parsing publicKeyInfo manually
            var asn1 = new AsnReader(certBytes, AsnEncodingRules.DER);
            var content = asn1.ReadSequence();
            var certData = content.ReadSequence();
            var version = certData.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            var serial = certData.ReadInteger();
            var signingAlg = certData.ReadSequence();
            var issuer = certData.ReadSequence();
            var validity = certData.ReadSequence();
            var subject = certData.ReadSequence();
            var publicKeyInfo = certData.ReadEncodedValue();

            // That's all we need
            return publicKeyInfo.ToArray();
#endif
        }

    }
}

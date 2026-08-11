using System.Formats.Asn1;
using System.Security.Cryptography;

namespace Rotherprivat.Cryptography.Internal
{
    internal static class ECAlgorithmExtension
    {
        public static byte[] ExportECPrivateKeyD(this ECDiffieHellman ecdh)
        {
            var ecParams = ecdh.ExportParameters(true);
            ecParams.Validate();
                
            var asn1 = new AsnWriter(AsnEncodingRules.DER);
            using (asn1.PushSequence())
            {
                asn1.WriteInteger(1);
                //AlgorithmIdentifier
                asn1.WriteOctetString(ecParams.D);
                using (asn1.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                {
                    asn1.WriteObjectIdentifier(ecParams.Curve.Oid.Value!);
                    //                    asn1.WriteNull();
                }
            }
            return asn1.Encode();
        }

        public static byte[] ExportECPublicKeyBytes (this ECParameters ecParams)
        {   
            ecParams.Validate();
            using MemoryStream s = new();
            using BinaryWriter w = new(s);
            w.Write((byte)0x04);
            w.Write(ecParams.Q.X!);
            w.Write(ecParams.Q.Y!);
            w.Close();
            return s.ToArray();
        }
    }
}

using System.Diagnostics.CodeAnalysis;
using System.Text.Json.Serialization;

namespace Rotherprivat.CompositeMLKemTest.Cryptography
{
#pragma warning disable IDE1006 // Naming Styles
    public class TestVector
    {
        [AllowNull]
        public string cacert { get; set; }

        [JsonPropertyName("tests")]
        public Test[]? testsJson
        { 
            get => [.. tests.Values];
            set
            {
                if (value == null)
                    return;

                foreach (Test test in value)
                    tests.Add(test.tcId, test);
            }
        }

        [JsonIgnore]
        public Dictionary<string, Test> tests { get; } = [];
    }

    public class Test
    {
        [AllowNull]
        public string tcId { get; set; }
        [AllowNull]
        public string ek { get; set; }
        [AllowNull]
        public string x5c { get; set; }
        [AllowNull]
        public string dk { get; set; }
        [AllowNull]
        public string dk_pkcs8 { get; set; }
        [AllowNull]
        public string c { get; set; }
        [AllowNull]
        public string k { get; set; }
    }
#pragma warning restore IDE1006 // Naming Styles
}

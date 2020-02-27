
using System;
using System.Text;
using CryptoCommons.Hashing;
using Xunit;

namespace CryptoCommons.Tests.Hashing
{
    public class TestSha512Hasher
    {

        [Fact]
        public void Decrypt_ValidCipherAndKey_ReturnsDecipheredString()
        {
            // Arrange
            var testStr = "letshashagain";
            var expectedReturn = "g8G5AGk+6AzVbB+wvh25qMMKP9sMbvv+VogLR7Bq3um6BFHSkFt9qeFo3rXkWmyLjEqImbygYZfgwystUwpddg==";

            // Act
            var hasher = new Sha512Hasher();
            var result = hasher.ComputeHash(Encoding.UTF8.GetBytes(testStr));

            // Assert
            Assert.Equal(expectedReturn, Convert.ToBase64String(result));
        }

    }
}

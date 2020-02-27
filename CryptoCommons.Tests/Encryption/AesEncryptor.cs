
using System.Security.Cryptography;
using CryptoCommons.Encryption;
using Xunit;

namespace CryptoCommons.Tests.Encryption
{
    public class TestAesEncryptor
    {
        [Fact]
        public void Decrypt_ValidCipherAndKey_ReturnsDecipheredString()
        {
            // Arrange
            var key = "cRfUjXn2r5u8x/A?D*G-KaPdSgVkYp3s";
            var testCipher = "6162636162636162Lkc4GPlB1v5LggAR3DCQ4A==";
            var expectedReturn = "encryptthis";
            var sut = new AesEncryptor();

            // Act
            var result = sut.Decrypt(testCipher, key);

            // Assert
            Assert.Equal(expectedReturn, result);
        }

        [Fact]
        public void Decrypt_InvalidKey_RaisesCryptographicException()
        {
            // Arrange
            var key = "thisissuchawrongkey";
            var testToken = "6162636162636162Lkc4GPlB1v5LggAR3DCQ4A==";
            var sut = new AesEncryptor();
            // Act & Assert
            Assert.Throws<CryptographicException>(
                () => sut.Decrypt(testToken, key));
        }


        [Theory]
        [InlineData("invalidCipher")]
        [InlineData(":")]
        [InlineData("")]
        public void Decrypt_InvalidCipherFormat_RaisesCryptographicException(string testToken)
        {
            // Arrange
            var key = "cRfUjXn2r5u8x/A?D*G-KaPdSgVkYp3s";
            var sut = new AesEncryptor();

            // Act & Assert
            Assert.Throws<CryptographicException>(
                () => sut.Decrypt(testToken, key));
        }

        [Fact]
        public void Decrypt_EmptyCipher_ReturnsEmptyString()
        {
            // Arrange
            var key = "cRfUjXn2r5u8x/A?D*G-KaPdSgVkYp3s";
            var testToken = "justIVnoContent!";
            var sut = new AesEncryptor();

            // Act
            var result = sut.Decrypt(testToken, key);

            // Assert
            Assert.True(string.IsNullOrEmpty(result));
        }

        [Fact]
        public void EncryptDecrypt_ValidStringAndKey_StringsMatch()
        {
            // Arrange
            var key = "cRfUjXn2r5u8x/A?D*G-KaPdSgVkYp3s";
            var testString = "pleaseletmego";
            var sut = new AesEncryptor();

            // Act
            var encrypted = sut.Encrypt(testString, key);
            var decrypted = sut.Decrypt(encrypted, key);

            // Assert
            Assert.Equal(testString, decrypted);
        }

        [Fact]
        public void EncryptDecrypt_InvalidKey_RaisesCryptographicException()
        {
            // Arrange
            var key = "badbadbadkey";
            var testString = "pleaseletmego";
            var sut = new AesEncryptor();

            // Act & Assert
            Assert.Throws<CryptographicException>(
                () => sut.Encrypt(testString, key));
        }
    }
}

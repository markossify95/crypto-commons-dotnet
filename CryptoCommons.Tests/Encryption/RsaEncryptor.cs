
using System.Security.Cryptography;
using CryptoCommons.Encryption;
using Xunit;

namespace CryptoCommons.Tests.Encryption
{
    public class TestRsaEncryptor
    {
        const string privateKey = @"-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQC5ocbTjGf2YuXdugtRVNAQMxTf8dEE/ZCfLIkKMHJcQw8RbYSB
LmSVPwBGkkfvgVcu6yH3UwUyKb0s/xBGmTba+QRrdyFjYbSsRXjmXmoskIO+zcJn
vBx4eFd01KZTmGXsEoFIBfpx5DDLxdh5szJhVTTv8hD/TOZPaokIZmWfvQIDAQAB
AoGAS4LOYVGVHLnALcC3R99LP7u3ux0f3HrU8JrqJ/XrHzK8F2fIZdAcZEWbdBmf
H4MqltBZIcVosK4f4QTkdwNuN1V/dbSMA+uCsnMEr/Ti5S3s3WnlWGb1Ow6HNtG4
eqZh07DeJoW6hC0CENgKq0FsozP+dh8K6kXyD/HphzoHspUCQQDeQQxthW90GEEE
PodddRwm+OEX+ZuhtQzVpM42Zmmr1I719RJFUdyX4625pEUI2U5ASXxUK3kyoDJB
lqvmgm2XAkEA1dE8VUWjhOpxGJQF0UCPdWHZcuJd12FXfcNWTSHc+KczHx9tGC1+
9P2ZLFlbH6MYoETEC29W8d8xTBQkezYvywJBAJH3otPjSPm0XC8PahPlMCIgXqVC
WAZyRAWkgZKU3F3v8hxzYhaI1xoifBxqWLShE5WBLdiR3L11HMyayjdP/e0CQQCF
Dmr8KZTjbr0obVzdZc6gXl7iFioNkN7QPVGkODF5bxrqADV0eUNrE7FRHt4M5wK5
IXHaJ9Q0Og9EZ7h4EDVXAkBOI2VdlNwKCoWNFVMvG18gYO4JUXrGu0Dbhxqg8c69
J9uTsD7b4GEcnxAS4sB7hIa/WcgXkO81qlBPNDq+dYw5
-----END RSA PRIVATE KEY-----";

        const string publicKey = @"-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC5ocbTjGf2YuXdugtRVNAQMxTf
8dEE/ZCfLIkKMHJcQw8RbYSBLmSVPwBGkkfvgVcu6yH3UwUyKb0s/xBGmTba+QRr
dyFjYbSsRXjmXmoskIO+zcJnvBx4eFd01KZTmGXsEoFIBfpx5DDLxdh5szJhVTTv
8hD/TOZPaokIZmWfvQIDAQAB
-----END PUBLIC KEY-----";

        [Fact]
        public void EncryptDecrypt_Valid_StringsMatch()
        {
            // Arrange
            var testString = "encryptthis";
            var sut = new RsaEncryptor();

            // Act
            var encrypted = sut.Encrypt(testString, publicKey);
            var result = sut.Decrypt(encrypted, privateKey);
            // Assert
            Assert.Equal(testString, result);
        }


        [Fact]
        public void EncryptPrivateDecryptPublic_Valid_StringsMatch()
        {
            // Arrange
            var testString = "encryptthis";
            var sut = new RsaEncryptor();

            // Act
            var encrypted = sut.EncryptPrivate(testString, privateKey);
            var result = sut.DecryptPublic(encrypted, publicKey);
            // Assert
            Assert.Equal(testString, result);
        }

    }
}

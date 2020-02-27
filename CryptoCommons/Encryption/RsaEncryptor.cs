
using System;
using System.IO;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.OpenSsl;

namespace CryptoCommons.Encryption
{
    public class RsaEncryptor
    {

        public string Encrypt(string clearText, string publicKey)
        {
            var bytesToEncrypt = System.Text.Encoding.UTF8.GetBytes(clearText);

            var encryptEngine = new Pkcs1Encoding(new RsaEngine());

            using (var txtreader = new StringReader(publicKey))
            {
                var keyParameter = (AsymmetricKeyParameter)new PemReader(txtreader).ReadObject();

                encryptEngine.Init(true, keyParameter);
            }

            var encrypted = Convert.ToBase64String(encryptEngine.ProcessBlock(bytesToEncrypt, 0, bytesToEncrypt.Length));
            return encrypted;

        }

        public string EncryptPrivate(string clearText, string privateKey)
        {
            var bytesToEncrypt = System.Text.Encoding.UTF8.GetBytes(clearText);

            var encryptEngine = new Pkcs1Encoding(new RsaEngine());

            using (var txtreader = new StringReader(privateKey))
            {
                var keyPair = (AsymmetricCipherKeyPair)new PemReader(txtreader).ReadObject();

                encryptEngine.Init(true, keyPair.Private);
            }

            var encrypted = Convert.ToBase64String(encryptEngine.ProcessBlock(bytesToEncrypt, 0, bytesToEncrypt.Length));
            return encrypted;
        }


        public string Decrypt(string base64Input, string privateKey)
        {
            var bytesToDecrypt = Convert.FromBase64String(base64Input);

            AsymmetricCipherKeyPair keyPair;
            var decryptEngine = new Pkcs1Encoding(new RsaEngine());

            using (var txtreader = new StringReader(privateKey))
            {
                keyPair = (AsymmetricCipherKeyPair)new PemReader(txtreader).ReadObject();

                decryptEngine.Init(false, keyPair.Private);
            }

            var decrypted = System.Text.Encoding.UTF8.GetString(
                decryptEngine.ProcessBlock(bytesToDecrypt, 0, bytesToDecrypt.Length));
            return decrypted;
        }

        public string DecryptPublic(string base64Input, string publicKey)
        {
            var bytesToDecrypt = Convert.FromBase64String(base64Input);

            var decryptEngine = new Pkcs1Encoding(new RsaEngine());

            using (var txtreader = new StringReader(publicKey))
            {
                var keyParameter = (AsymmetricKeyParameter)new PemReader(txtreader).ReadObject();

                decryptEngine.Init(false, keyParameter);
            }

            var decrypted = System.Text.Encoding.UTF8.GetString(
                decryptEngine.ProcessBlock(bytesToDecrypt, 0, bytesToDecrypt.Length));
            return decrypted;
        }
    }
}

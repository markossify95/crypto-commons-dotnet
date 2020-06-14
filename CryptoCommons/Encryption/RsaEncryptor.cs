
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

        private AsymmetricKeyParameter ReadPrivateKey(string privateKey)
        {
            using (var txtreader = new StringReader(privateKey))
            {
                var keyInstance = new PemReader(txtreader).ReadObject();
                if (keyInstance == null)
                    throw new FormatException("The key has an invalid PEM format.");
                if (keyInstance is AsymmetricKeyParameter)
                {
                    return (AsymmetricKeyParameter)keyInstance!;
                }
                if (keyInstance is AsymmetricCipherKeyPair)
                {
                    var pair = (AsymmetricCipherKeyPair)keyInstance!;
                    return pair!.Private;
                }
                throw new FormatException("The given key does not have the correct type. The keyfile must include the private and public key in PEM format. It is of type: " +
                                      keyInstance.GetType());
            }
        }

        public string EncryptPrivate(string clearText, string privateKey)
        {
            var bytesToEncrypt = System.Text.Encoding.UTF8.GetBytes(clearText);
            var encryptEngine = new Pkcs1Encoding(new RsaEngine());
            
            var keyParameter = ReadPrivateKey(privateKey);
            encryptEngine.Init(true, keyParameter);
            
            var encrypted = Convert.ToBase64String(
                encryptEngine.ProcessBlock(bytesToEncrypt, 0, bytesToEncrypt.Length));
            return encrypted;
        }


        public string Decrypt(string base64Input, string privateKey)
        {
            var bytesToDecrypt = Convert.FromBase64String(base64Input);
            var decryptEngine = new Pkcs1Encoding(new RsaEngine());

            var keyParameter = ReadPrivateKey(privateKey);
            decryptEngine.Init(false, keyParameter);

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

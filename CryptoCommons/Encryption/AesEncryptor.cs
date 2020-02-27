
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CryptoCommons.Encryption
{
    public class AesEncryptor
    {
        public string Decrypt(string cipherText, string key)
        {
            if (cipherText.Length < 16)
                throw new CryptographicException($"Invalid payload: {cipherText}");

            try
            {
                byte[] iv = System.Text.Encoding.UTF8.GetBytes(cipherText.Substring(0, 16));
                byte[] cipherBytes = Convert.FromBase64String(cipherText.Substring(16));

                using (var aesAlg = Aes.Create())
                {
                    aesAlg.Key = System.Text.Encoding.UTF8.GetBytes(key);
                    aesAlg.IV = iv;

                    var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                    using var msDecrypt = new MemoryStream(cipherBytes);
                    using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
                    using var srDecrypt = new StreamReader(csDecrypt);
                    return srDecrypt.ReadToEnd();
                }
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (IndexOutOfRangeException)
            {
                var msg = $"Invalid cipher format: {cipherText}";
                throw new CryptographicException(msg);
            }
            catch (FormatException)
            {
                var msg = $"Invalid cipher format: {cipherText}";
                throw new CryptographicException(msg);
            }
        }

        public string Encrypt(string plainText, string key)
        {
            try
            {
                byte[] result;
                string ivStr;
                using (var aesAlg = Aes.Create())
                {
                    aesAlg.Key = System.Text.Encoding.UTF8.GetBytes(key);
                    Random rnd = new Random();
                    Byte[] iv = new Byte[8];
                    rnd.NextBytes(iv);
                    ivStr = ToHexString(iv);
                    aesAlg.IV = System.Text.Encoding.UTF8.GetBytes(ivStr);

                    var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                    using (var msEncrypt = new MemoryStream())
                    {
                        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        {
                            using (var swEncrypt = new StreamWriter(csEncrypt))
                            {
                                swEncrypt.Write(plainText);
                            }
                            result = msEncrypt.ToArray();
                        }
                    }
                }
                return ivStr + Convert.ToBase64String(result, 0, result.Length);
            }
            catch (CryptographicException)
            {
                throw;
            }
        }

        public string ToHexString(byte[] byteStr)
        {
            var sb = new StringBuilder();

            var bytes = byteStr;
            foreach (var t in bytes)
            {
                sb.Append(t.ToString("X2"));
            }

            return sb.ToString();
        }

        public byte[] FromHexString(string hexString)
        {
            var bytes = new byte[hexString.Length / 2];
            for (var i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);
            }

            return bytes;
        }
    }
}

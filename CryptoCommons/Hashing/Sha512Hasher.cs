using System.Security.Cryptography;

namespace CryptoCommons.Hashing
{
    public class Sha512Hasher
    {
        public byte[] ComputeHash(byte[] data)
        {
            SHA512 shaM = new SHA512Managed();
            return shaM.ComputeHash(data);
        }
    }
}

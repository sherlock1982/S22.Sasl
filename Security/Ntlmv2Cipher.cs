using System;
using System.Linq;
using System.Security.Cryptography;

namespace S22.Sasl.Security
{
    /// <summary>
    /// NTLMv2 SASL cipher implementation
    /// </summary>
    public class Ntlmv2Cipher : ISaslCipher, IDisposable
    {
        static readonly byte[] ClientToServerSigningKeyMagic = StringToByteArray(
            "73657373696f6e206b657920746f20636c69656e742d746f2d736572766572207369676e696e67206b6579206d6167696320636f6e7374616e7400");
        static readonly byte[] ServerToClientSigningKeyMagic = StringToByteArray(
            "73657373696f6e206b657920746f207365727665722d746f2d636c69656e74207369676e696e67206b6579206d6167696320636f6e7374616e7400");

        static readonly byte[] ClientToServerSealingKeyMagic = StringToByteArray(
            "73657373696f6e206b657920746f20636c69656e742d746f2d736572766572207365616c696e67206b6579206d6167696320636f6e7374616e7400");
        static readonly byte[] ServerToClientSealingKeyMagic = StringToByteArray(
            "73657373696f6e206b657920746f207365727665722d746f2d636c69656e74207365616c696e67206b6579206d6167696320636f6e7374616e7400");

        readonly Ntlmv2Encoder _encoder;
        readonly Ntlmv2Decoder _decoder;

        public const int SealLength = 8;
        public const int Version = 1;

        public Ntlmv2Cipher(byte[] masterSessionKey)
        {
            using (var md5 = MD5.Create())
            {
                _encoder = new Ntlmv2Encoder(
                    GenerateSubkey(masterSessionKey, ClientToServerSigningKeyMagic, md5), 
                    GenerateSubkey(masterSessionKey, ClientToServerSealingKeyMagic, md5));

                _decoder = new Ntlmv2Decoder(
                    GenerateSubkey(masterSessionKey, ServerToClientSigningKeyMagic, md5),
                    GenerateSubkey(masterSessionKey, ServerToClientSealingKeyMagic, md5));
            }
        }

        public void Dispose()
        {
            _encoder.Dispose();
            _decoder.Dispose();
        }

        public byte[] EncodeMessage(byte[] buffer, int offset, int count)
        {
            return _encoder.EncodeMessage(buffer, offset, count);
        }

        public int DecodeMessage(byte[] buffer, int offset, int count, byte[] output, int outOff)
        {
            return _decoder.DecodeMessage(buffer, offset, count, output, outOff);
        }

        static byte[] GenerateSubkey(byte[] masterSessionKey, byte[] magicConstant, HashAlgorithm hash)
        {
            var combinedKey = new byte[masterSessionKey.Length + magicConstant.Length];
            Array.Copy(masterSessionKey, combinedKey, masterSessionKey.Length);
            Array.Copy(magicConstant, 0, combinedKey, masterSessionKey.Length, magicConstant.Length);

            return hash.ComputeHash(combinedKey);
        }

        static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length).Where(x => x % 2 == 0).Select(x => Convert.ToByte(hex.Substring(x, 2), 16)).ToArray();
        }

    }
}

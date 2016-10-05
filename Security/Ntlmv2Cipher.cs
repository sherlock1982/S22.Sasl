using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Linq;
using System.Security.Cryptography;

namespace S22.Sasl.Security
{
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

        int _sequence;
        readonly HashAlgorithm _clientSigning;
        readonly RC4Engine _clientSealing;
        readonly byte[] _sealedConcat = new byte[8];
        const int Version = 1;
        readonly object _encodeSync = new object();

        public Ntlmv2Cipher(byte[] masterSessionKey)
        {
            using (var md5 = MD5.Create())
            {
                byte[] clientSigningKey = GenerateSubkey(masterSessionKey, ClientToServerSigningKeyMagic, md5),
                       clientSealingKey = GenerateSubkey(masterSessionKey, ClientToServerSealingKeyMagic, md5);

                _clientSealing = new RC4Engine();
                _clientSealing.Init(true, new KeyParameter(clientSealingKey));

                _clientSigning = new HMACMD5(clientSigningKey);
            }
        }

        public void Dispose()
        {
            _clientSigning.Dispose();
        }

        public byte[] EncodeMessage(byte[] msg)
        {
            lock (_encodeSync)
            {
                var @sealed = new byte[msg.Length];
                _clientSealing.ProcessBytes(msg, 0, msg.Length, @sealed, 0);

                var concat = new ByteBuilder().Append(_sequence).Append(msg).ToArray();
                var concatHash = _clientSigning.ComputeHash(concat);
                _clientSealing.ProcessBytes(concatHash, 0, 8, _sealedConcat, 0);

                var signed = new ByteBuilder().Append(Version).Append(_sealedConcat).Append(_sequence).Append(@sealed).ToArray();
                _sequence++;
                return signed;
            }
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

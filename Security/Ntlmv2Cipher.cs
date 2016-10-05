using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
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

        int _sequence;
        readonly HashAlgorithm _clientSigning;
        readonly RC4Engine _clientSealing;
        readonly RC4Engine _serverSealing;
        readonly byte[] _sealedConcat = new byte[8];
        const int Version = 1;
        const int SealLength = 16;
        readonly object _encodeSync = new object();

        public Ntlmv2Cipher(byte[] masterSessionKey)
        {
            using (var md5 = MD5.Create())
            {
                byte[] clientSigningKey = GenerateSubkey(masterSessionKey, ClientToServerSigningKeyMagic, md5),
                       clientSealingKey = GenerateSubkey(masterSessionKey, ClientToServerSealingKeyMagic, md5),
                       serverSealingKey = GenerateSubkey(masterSessionKey, ServerToClientSealingKeyMagic, md5);

                _clientSealing = new RC4Engine();
                _clientSealing.Init(true, new KeyParameter(clientSealingKey));

                _serverSealing = new RC4Engine();
                _serverSealing.Init(false, new KeyParameter(serverSealingKey));

                _clientSigning = new HMACMD5(clientSigningKey);
            }
        }

        public void Dispose()
        {
            _clientSigning.Dispose();
        }

        public byte[] EncodeMessage(byte[] buffer, int offset, int count)
        {
            lock (_encodeSync)
            {
                var @sealed = new byte[count];
                _clientSealing.ProcessBytes(buffer, offset, count, @sealed, 0);

                var concatHash = _clientSigning.ComputeHash(new ByteBuilder().Append(_sequence).Append(buffer, offset, count).ToArray());
                _clientSealing.ProcessBytes(concatHash, 0, 8, _sealedConcat, 0);

                var signed = new ByteBuilder().Append(Version).Append(_sealedConcat).Append(_sequence).Append(@sealed).ToArray();
                _sequence++;
                return signed;
            }
        }

        public int DecodeMessage(byte[] buffer, int offset, int count, byte[] output, int outOff)
        {
            // TODO check sealing
            _serverSealing.ProcessBytes(buffer, offset + SealLength, count - SealLength, output, outOff);
            return count - SealLength;
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

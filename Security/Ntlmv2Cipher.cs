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

        int _clientSequence;
        readonly HashAlgorithm _clientSigning;
        readonly HashAlgorithm _serverSigning;
        readonly RC4Engine _clientSealing;
        readonly RC4Engine _serverSealing;
        readonly byte[] _clientSeal = new byte[SealLength];
        readonly byte[] _serverSeal = new byte[SealLength];
        const int SealLength = 8;
        const int Version = 1;
        const int SealOffset = 4;
        const int SequenceOffset = 12;
        const int MessageOffset = 16;
        readonly object _encodeSync = new object();
        readonly object _decodeSync = new object();

        public Ntlmv2Cipher(byte[] masterSessionKey)
        {
            using (var md5 = MD5.Create())
            {
                byte[] clientSigningKey = GenerateSubkey(masterSessionKey, ClientToServerSigningKeyMagic, md5),
                       clientSealingKey = GenerateSubkey(masterSessionKey, ClientToServerSealingKeyMagic, md5),
                       serverSigningKey = GenerateSubkey(masterSessionKey, ServerToClientSigningKeyMagic, md5),
                       serverSealingKey = GenerateSubkey(masterSessionKey, ServerToClientSealingKeyMagic, md5);

                _clientSealing = new RC4Engine();
                _clientSealing.Init(true, new KeyParameter(clientSealingKey));

                _serverSealing = new RC4Engine();
                _serverSealing.Init(false, new KeyParameter(serverSealingKey));

                _clientSigning = new HMACMD5(clientSigningKey);
                _serverSigning = new HMACMD5(serverSigningKey);
            }
        }

        public void Dispose()
        {
            _clientSigning.Dispose();
            _serverSigning.Dispose();
        }

        public byte[] EncodeMessage(byte[] buffer, int offset, int count)
        {
            lock (_encodeSync)
            {
                using (var builder = new ByteBuilder())
                {
                    var @sealed = new byte[count];
                    _clientSealing.ProcessBytes(buffer, offset, count, @sealed, 0);

                    var concatHash = _clientSigning.ComputeHash(builder.Append(_clientSequence).Append(buffer, offset, count).ToArray());
                    builder.Clear();
                    _clientSealing.ProcessBytes(concatHash, 0, _clientSeal.Length, _clientSeal, 0);

                    var signed = builder.Append(Version).Append(_clientSeal).Append(_clientSequence).Append(@sealed).ToArray();
                    _clientSequence++;
                    return signed;
                }
            }
        }

        public int DecodeMessage(byte[] buffer, int offset, int count, byte[] output, int outOff)
        {
            lock (_decodeSync)
            {
                _serverSealing.ProcessBytes(buffer, offset + MessageOffset, count - MessageOffset, output, outOff);
                _serverSealing.ProcessBytes(buffer, offset + SealOffset, _serverSeal.Length, _serverSeal, 0);
                //var serverSequence = BitConverter.ToUInt32(buffer, SequenceOffset);
                using (var builder = new ByteBuilder())
                {
                    var concatHash = _serverSigning.ComputeHash(builder.Append(buffer, SequenceOffset, 4).Append(output, outOff, count - MessageOffset).ToArray());

                    if (!_serverSeal.SequenceEqual(concatHash.Take(SealLength)))
                        throw new Exception("Server signature check failed");
                    return count - MessageOffset;
                }
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

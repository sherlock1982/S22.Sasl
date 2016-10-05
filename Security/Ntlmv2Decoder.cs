using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Linq;
using System.Security.Cryptography;

namespace S22.Sasl.Security
{
    public class Ntlmv2Decoder : IDisposable
    {
        const int SealOffset = 4;
        const int SequenceOffset = 12;
        const int MessageOffset = 16;

        readonly HashAlgorithm _signing;
        readonly RC4Engine _sealing;
        readonly byte[] _seal = new byte[Ntlmv2Cipher.SealLength];
        readonly ByteBuilder _builder = new ByteBuilder();
        readonly object _sync = new object();

        public Ntlmv2Decoder(byte[] serverSigningKey, byte[] serverSealingKey)
        {
            _sealing = new RC4Engine();
            _sealing.Init(false, new KeyParameter(serverSealingKey));

            _signing = new HMACMD5(serverSigningKey);
        }

        public int DecodeMessage(byte[] buffer, int offset, int count, byte[] output, int outOff)
        {
            lock (_sync)
            {
                _sealing.ProcessBytes(buffer, offset + MessageOffset, count - MessageOffset, output, outOff);
                _sealing.ProcessBytes(buffer, offset + SealOffset, _seal.Length, _seal, 0);
                var concatHash = _signing.ComputeHash(_builder.Append(buffer, SequenceOffset, 4).Append(output, outOff, count - MessageOffset).ToArray());
                _builder.Clear();

                if (!_seal.SequenceEqual(concatHash.Take(Ntlmv2Cipher.SealLength)))
                    throw new Exception("Server signature check failed");
                return count - MessageOffset;
            }
        }

        public void Dispose()
        {
            lock (_sync)
            {
                _signing.Dispose();
                _builder.Dispose();
            }
        }
    }
}

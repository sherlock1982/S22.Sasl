using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Security.Cryptography;

namespace S22.Sasl.Security
{
    public class Ntlmv2Encoder : IDisposable
    {
        readonly object _sync = new object();
        readonly RC4Engine _sealing;
        readonly HashAlgorithm _signing;
        readonly ByteBuilder _builder = new ByteBuilder();
        readonly byte[] _seal = new byte[Ntlmv2Cipher.SealLength];

        int _clientSequence;

        public Ntlmv2Encoder(byte[] clientSigningKey, byte[] clientSealingKey)
        {
            _sealing = new RC4Engine();
            _sealing.Init(true, new KeyParameter(clientSealingKey));

            _signing = new HMACMD5(clientSigningKey);
        }

        public byte[] EncodeMessage(byte[] buffer, int offset, int count)
        {
            lock (_sync)
            {
                var @sealed = new byte[count];
                _sealing.ProcessBytes(buffer, offset, count, @sealed, 0);

                var concatHash = _signing.ComputeHash(_builder.Append(_clientSequence).Append(buffer, offset, count).ToArray());
                _builder.Clear();
                _sealing.ProcessBytes(concatHash, 0, _seal.Length, _seal, 0);

                var signed = _builder.Append(Ntlmv2Cipher.Version).Append(_seal).Append(_clientSequence).Append(@sealed).ToArray();
                _builder.Clear();
                _clientSequence++;
                return signed;
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

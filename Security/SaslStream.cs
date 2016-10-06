using System;
using System.IO;

namespace S22.Sasl.Security
{
    /// <summary>
    /// SASL stream with supporting encoding and decoding of messages
    /// </summary>
    public class SaslStream : Stream
    {
        const long TruncateLength = 1024 * 10;
        readonly Stream _innerStream;
        readonly ISaslCipher _cipher;
        readonly byte[] _size = new byte[4];
        byte[] _buffer;
        byte[] _decodeBuffer;
        MemoryStream _bufferStream = new MemoryStream();

        public SaslStream(Stream innerStream, ISaslCipher cipher)
        {
            _innerStream = innerStream;
            _cipher = cipher;
        }

        public override bool CanRead
        {
            get
            {
                return true;
            }
        }

        public override bool CanSeek
        {
            get
            {
                return false;
            }
        }

        public override bool CanWrite
        {
            get
            {
                return true;
            }
        }

        public override long Length
        {
            get
            {
                throw new NotSupportedException();
            }
        }

        public override long Position
        {
            get
            {
                throw new NotSupportedException();
            }
            set
            {
                throw new NotSupportedException();
            }
        }

        public override void Flush()
        {
            _innerStream.Flush();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            while(_bufferStream.Position + count > _bufferStream.Length)
            {
                var messageLength = ReadMessage();

                var readPosition = _bufferStream.Position;
                // Write decoded message to buffer end
                _bufferStream.Seek(0, SeekOrigin.End);
                _bufferStream.Write(_decodeBuffer, 0, messageLength);
                // Restore read position
                _bufferStream.Seek(readPosition, SeekOrigin.Begin);
            }
            // Have enough data to read
            var bytesRead = _bufferStream.Read(buffer, offset, count);
            Truncate();

            return bytesRead;
        }

        int ReadMessage()
        {
            // Read size
            if (_innerStream.Read(_size, 0, 4) != 4)
                throw new IOException();
            var messageLength = (_size[0] << 24) | (_size[1] << 16)
                      | (_size[2] << 8) | _size[3];
            if (_buffer == null || _buffer.Length < messageLength)
            {
                _buffer = new byte[messageLength];
                _decodeBuffer = new byte[messageLength];
            }

            // Read message
            var bytesRead = 0;
            while(bytesRead < messageLength)
            {
                var packetBytesRead = _innerStream.Read(_buffer, bytesRead, messageLength - bytesRead);
                if (packetBytesRead == 0)
                    throw new IOException();
                bytesRead += packetBytesRead;
            }
            return _cipher.DecodeMessage(_buffer, 0, messageLength, _decodeBuffer, 0);
        }

        private void Truncate()
        {
            if (_bufferStream.Position > 0 && _bufferStream.Length > TruncateLength )
            {
                var newStream = new MemoryStream();

                _bufferStream.CopyTo(newStream);
                _bufferStream.Dispose();
                _bufferStream = newStream;

                _bufferStream.Seek(0, SeekOrigin.Begin);
            }
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            var encoded = _cipher.EncodeMessage(buffer, offset, count);

            var data = new ByteBuilder().Append(encoded.Length, true).Append(encoded).ToArray();
            _innerStream.Write(data, 0, data.Length);
        }


    }
}

using System;
using System.IO;
using System.Linq;
using System.Text;

namespace S22.Sasl {
	/// <summary>
	/// A utility class modeled after the BCL StringBuilder to simplify
	/// building binary-data messages.
	/// </summary>
	public class ByteBuilder : IDisposable {
		/// <summary>
		/// The actual byte buffer.
		/// </summary>
		MemoryStream buffer = new MemoryStream(1024);
        BinaryWriter writer;

		/// <summary>
		/// The length of the underlying data buffer.
		/// </summary>
		public long Length {
			get {
				return buffer.Position;
			}
		}

        public ByteBuilder()
        {
            writer = new BinaryWriter(buffer);
        }

		/// <summary>
		/// Appends one or several byte values to this instance.
		/// </summary>
		/// <param name="values">Byte values to append.</param>
		/// <returns>A reference to the calling instance.</returns>
		public ByteBuilder Append(params byte[] values) {
            writer.Write(values);
			return this;
		}

		/// <summary>
		/// Appends the specified number of bytes from the specified buffer
		/// starting at the specified offset to this instance.
		/// </summary>
		/// <param name="buffer">The buffer to append bytes from.</param>
		/// <param name="offset">The offset into the buffert at which to start
		/// reading bytes from.</param>
		/// <param name="count">The number of bytes to read from the buffer.</param>
		/// <returns>A reference to the calling instance.</returns>
		public ByteBuilder Append(byte[] buffer, int offset, int count) {
            writer.Write(buffer, offset, count);
            return this;
		}

		/// <summary>
		/// Appends the specified 32-bit integer value to this instance.
		/// </summary>
		/// <param name="value">A 32-bit integer value to append.</param>
		/// <param name="bigEndian">Set this to true, to append the value as
		/// big-endian.</param>
		/// <returns>A reference to the calling instance.</returns>
		public ByteBuilder Append(int value, bool bigEndian = false) {
            var buffer = BitConverter.GetBytes(value);
            if (bigEndian)
                buffer = buffer.Reverse().ToArray();
            writer.Write(buffer);
			return this;
		}

		/// <summary>
		/// Appends the specified 16-bit short value to this instance.
		/// </summary>
		/// <param name="value">A 16-bit short value to append.</param>
		/// <param name="bigEndian">Set this to true, to append the value as
		/// big-endian.</param>
		/// <returns>A reference to the calling instance.</returns>
		public ByteBuilder Append(short value, bool bigEndian = false) {
            var buffer = BitConverter.GetBytes(value);
            if (bigEndian)
                buffer = buffer.Reverse().ToArray();
            writer.Write(buffer);
            return this;
		}

		/// <summary>
		/// Appends the specified 16-bit unsigend short value to this instance.
		/// </summary>
		/// <param name="value">A 16-bit unsigend short value to append.</param>
		/// <param name="bigEndian">Set this to true, to append the value as
		/// big-endian.</param>
		/// <returns>A reference to the calling instance.</returns>
		public ByteBuilder Append(ushort value, bool bigEndian = false) {
            var buffer = BitConverter.GetBytes(value);
            if (bigEndian)
                buffer = buffer.Reverse().ToArray();
            writer.Write(buffer);
            return this;
		}

		/// <summary>
		/// Appends the specified 32-bit unsigned integer value to this instance.
		/// </summary>
		/// <param name="value">A 32-bit unsigned integer value to append.</param>
		/// <param name="bigEndian">Set this to true, to append the value as
		/// big-endian.</param>
		/// <returns>A reference to the calling instance.</returns>
		public ByteBuilder Append(uint value, bool bigEndian = false) {
            var buffer = BitConverter.GetBytes(value);
            if (bigEndian)
                buffer = buffer.Reverse().ToArray();
            writer.Write(buffer);
            return this;
		}

		/// <summary>
		/// Appends the specified 64-bit integer value to this instance.
		/// </summary>
		/// <param name="value">A 64-bit integer value to append.</param>
		/// <param name="bigEndian">Set this to true, to append the value as
		/// big-endian.</param>
		/// <returns>A reference to the calling instance.</returns>
		public ByteBuilder Append(long value, bool bigEndian = false) {
            var buffer = BitConverter.GetBytes(value);
            if (bigEndian)
                buffer = buffer.Reverse().ToArray();
            writer.Write(buffer);
            return this;
		}

		/// <summary>
		/// Appends the specified string using the specified encoding to this
		/// instance.
		/// </summary>
		/// <param name="value">The string vale to append.</param>
		/// <param name="encoding">The encoding to use for decoding the string value
		/// into a sequence of bytes. If this is null, ASCII encoding is used as a
		/// default.</param>
		/// <returns>A reference to the calling instance.</returns>
		public ByteBuilder Append(string value, Encoding encoding = null) {
            if (encoding == null)
                encoding = Encoding.ASCII;
            writer.Write(encoding.GetBytes(value));
			return this;
		}

		/// <summary>
		/// Returns the ByteBuilder's content as an array of bytes.
		/// </summary>
		/// <returns>An array of bytes.</returns>
		public byte[] ToArray() {
			return buffer.ToArray();
		}

		/// <summary>
		/// Removes all bytes from the current ByteBuilder instance.
		/// </summary>
		public void Clear() {
            buffer.SetLength(0);
		}

        public void Dispose()
        {
            buffer.Dispose();
        }
    }
}

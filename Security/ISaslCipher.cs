namespace S22.Sasl.Security
{
    /// <summary>
    /// Interface describing SASL cipher
    /// </summary>
    public interface ISaslCipher
    {

        /// <summary>
        /// Encode message
        /// </summary>
        /// <param name="buffer">Input buffer</param>
        /// <param name="offset">Input buffer offset</param>
        /// <param name="count">Input message length</param>
        /// <returns></returns>
        byte[] EncodeMessage(byte[] buffer, int offset, int count);

        /// <summary>
        /// Decode message
        /// </summary>
        /// <param name="buffer">Input buffer</param>
        /// <param name="offset">Input buffer offset</param>
        /// <param name="count">Input message length</param>
        /// <param name="output">Output buffer</param>
        /// <param name="outOff">Output buffer offset</param>
        /// <returns>Output message length</returns>
        int DecodeMessage(byte[] buffer, int offset, int count, byte[] output, int outOff);
    }
}

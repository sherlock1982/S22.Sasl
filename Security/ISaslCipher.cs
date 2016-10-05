using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace S22.Sasl.Security
{
    public interface ISaslCipher
    {
        byte[] EncodeMessage(byte[] msg);
    }
}

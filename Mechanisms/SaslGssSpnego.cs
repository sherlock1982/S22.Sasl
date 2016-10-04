using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace S22.Sasl.Mechanisms
{
    public class SaslGssSpnego : SaslNtlmv2
    {
        public SaslGssSpnego(NetworkCredential credential)
            : base(credential)
        {

        }

        public override string Name
        {
            get
            {
                return "GSS-SPNEGO";
            }
        }
    }
}

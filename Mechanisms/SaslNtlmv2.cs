using S22.Sasl.Mechanisms.Ntlm;
using System;
using System.Net;

namespace S22.Sasl.Mechanisms {
    /// <summary>
    /// Implements the Sasl NTLMv2 authentication method which addresses
    /// some of the security issues present in NTLM version 1.
    /// </summary>
    public class SaslNtlmv2 : SaslNtlm {

        readonly Flags _additionalFlags;

		/// <summary>
		/// Private constructor for use with Sasl.SaslFactory.
		/// </summary>
		protected SaslNtlmv2() {
			// Nothing to do here.
		}

		/// <summary>
		/// Creates and initializes a new instance of the SaslNtlmv2 class
		/// using the specified username and password.
		/// </summary>
		/// <param name="username">The username to authenticate with.</param>
		/// <param name="password">The plaintext password to authenticate
		/// with.</param>
		/// <exception cref="ArgumentNullException">Thrown if the username
		/// or the password parameter is null.</exception>
		/// <exception cref="ArgumentException">Thrown if the username
		/// parameter is empty.</exception>
		public SaslNtlmv2(NetworkCredential credential, bool secure = false)
			: base(credential) {
            if (secure)
                _additionalFlags = Flags.NegotiateNTLM2Key | Flags.NegotiateSeal | Flags.NegotiateSign | Flags.Negotiate128 | Flags.NegotiateKeyExchange;
        }

		/// <summary>
		/// Computes the client response to the specified NTLM challenge.
		/// </summary>
		/// <param name="challenge">The challenge sent by the server</param>
		/// <returns>The response to the NTLM challenge.</returns>
		/// <exception cref="SaslException">Thrown if the response could not
		/// be computed.</exception>
		protected override byte[] ComputeResponse(byte[] challenge) {
			if (step == 1)
				completed = true;
			byte[] ret = step == 0 ? ComputeInitialResponse(challenge) :
				ComputeChallengeResponse(challenge);
			step = step + 1;
			return ret;
		}

        /// <summary>
        /// Computes the initial client response to an NTLM challenge.
        /// </summary>
        /// <param name="challenge">The challenge sent by the server. Since
        /// NTLM expects an initial client response, this will usually be
        /// empty.</param>
        /// <returns>The initial response to the NTLM challenge.</returns>
        /// <exception cref="SaslException">Thrown if the response could not
        /// be computed.</exception>
        protected override byte[] ComputeInitialResponse(byte[] challenge)
        {
            try
            {
                string domain = Properties.ContainsKey("Domain") ?
                    Properties["Domain"] as string : "domain";
                string workstation = Properties.ContainsKey("Workstation") ?
                    Properties["Workstation"] as string : "workstation";
                Type1Message msg = new Type1Message(domain, workstation, _additionalFlags);

                return msg.Serialize();
            }
            catch (Exception e)
            {
                throw new SaslException("The initial client response could not " +
                    "be computed.", e);
            }
        }

        /// <summary>
        /// Computes the actual challenge response to an NTLM challenge
        /// which is sent as part of an NTLM type 2 message.
        /// </summary>
        /// <param name="challenge">The challenge sent by the server.</param>
        /// <returns>The response to the NTLM challenge.</returns>
        /// <exception cref="SaslException">Thrown if the challenge
        /// response could not be computed.</exception>
        protected new byte[] ComputeChallengeResponse(byte[] challenge) {
			try {
				Type2Message msg = Type2Message.Deserialize(challenge);
                // This creates an NTLMv2 challenge response.
                var type3Message = new Type3Message(Credential, msg.Challenge,
                    Credential.UserName, _additionalFlags, true, msg.TargetName,
                    msg.RawTargetInformation);
                SessionKey = type3Message.SessionKey;

                return type3Message.Serialize();
			} catch (Exception e) {
				throw new SaslException("The challenge response could not be " +
					"computed.", e);
			}
		}

        public byte[] SessionKey { get; private set; }
    }
}

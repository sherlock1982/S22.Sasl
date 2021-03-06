﻿using S22.Sasl.Mechanisms.Ntlm;
using System;
using System.Net;

namespace S22.Sasl.Mechanisms {
    /// <summary>
    /// Implements the Sasl NTLM authentication method which is used in various
    /// Microsoft network protocol implementations.
    /// </summary>
    /// <remarks>Implemented with the help of the excellent documentation on
    /// NTLM composed by Eric Glass.</remarks>
    public class SaslNtlm : SaslMechanism {
		protected bool completed = false;

		/// <summary>
		/// NTLM involves several steps.
		/// </summary>
		protected int step = 0;

		/// <summary>
		/// Client sends the first message in the authentication exchange.
		/// </summary>
		public override bool HasInitial {
			get {
				return true;
			}
		}

		/// <summary>
		/// True if the authentication exchange between client and server
		/// has been completed.
		/// </summary>
		public override bool IsCompleted {
			get {
				return completed;
			}
		}

		/// <summary>
		/// The IANA name for the NTLM authentication mechanism.
		/// </summary>
		public override string Name {
			get {
				return "NTLM";
			}
		}

		/// <summary>
		/// The username to authenticate with.
		/// </summary>
		protected NetworkCredential Credential {
			get {
				return Properties.ContainsKey("Credential") ?
					Properties["Credential"] as NetworkCredential : null;
			}
			set {
				Properties["Credential"] = value;
			}
		}

		/// <summary>
		/// Private constructor for use with Sasl.SaslFactory.
		/// </summary>
		protected SaslNtlm() {
			// Nothing to do here.
		}

		/// <summary>
		/// Creates and initializes a new instance of the SaslNtlm class
		/// using the specified username and password.
		/// </summary>
		/// <param name="username">The username to authenticate with.</param>
		/// <param name="password">The plaintext password to authenticate
		/// with.</param>
		/// <exception cref="ArgumentNullException">Thrown if the username
		/// or the password parameter is null.</exception>
		/// <exception cref="ArgumentException">Thrown if the username
		/// parameter is empty.</exception>
		public SaslNtlm(NetworkCredential credential) {
			credential.UserName.ThrowIfNull("username");
			if (credential.UserName == String.Empty)
				throw new ArgumentException("The username must not be empty.");
            credential.Password.ThrowIfNull("password");

            Credential = credential;
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
		protected virtual byte[] ComputeInitialResponse(byte[] challenge) {
			try {
				string domain = Properties.ContainsKey("Domain") ?
					Properties["Domain"] as string : "domain";
				string workstation = Properties.ContainsKey("Workstation") ?
					Properties["Workstation"] as string : "workstation";
				Type1Message msg = new Type1Message(domain, workstation);

				return msg.Serialize();
			} catch (Exception e) {
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
		protected byte[] ComputeChallengeResponse(byte[] challenge) {
			try {
				Type2Message msg = Type2Message.Deserialize(challenge);
				byte[] data = new Type3Message(Credential, msg.Challenge,
					"Workstation").Serialize();
				return data;
			} catch (Exception e) {
				throw new SaslException("The challenge response could not be " +
					"computed.", e);
			}
		}
	}
}

### Introduction

This repository contains a .NET assembly implementing the "Authentication and Security Layer" (SASL)
framework. SASL specifies a protocol for authentication and optional establishment of a security
layer between client and server applications and is used by internet protocols such as IMAP, POP3,
SMTP, XMPP and others.


### Usage & Examples

To use the library add the S22.Sasl.Core.dll assembly to your project references in Visual Studio. Here's
a simple example which instantiates a new instance of the Digest-Md5 authentication mechanism and
demonstrates how it can be used to perform authentication.

    using System;
    using S22.Sasl;
    using System.Net;

    namespace Test
    {
        class Program
        {
            static void Main(string[] args)
            {
                SaslMechanism m = SaslFactory.Create("DIGEST-MD5");

                // Add properties needed by authentication mechanism.
                m.Properties.Add("Credential", new NetworkCredential("Foo", "Bar"));

                byte[] challenge = null;
                while (!m.IsCompleted)
                {
                    challenge = m.GetResponse(challenge);
                    SendMyDataToServer(challenge);

                    challenge = ReceiveMyDataFromServer();
                }
            }
        }
    }

Here's a more advanced example to create NTLMv2 secure channel.

    using System;
    using S22.Sasl;
    using System.Net;
    using S22.Sasl.Mechanisms;
    using S22.Sasl.Security;
    using System.IO;

    namespace Test
    {
        class Program
        {
            static void Main(string[] args)
            {
                var m = new SaslNtlmv2(new NetworkCredential("Foo", "Bar"), true);
                // This is your server stream
                Stream serverStream;

                byte[] challenge = null;
                while (!m.IsCompleted)
                {
                    challenge = m.GetResponse(challenge);
                    // Send and receive authentication data from server
                    SendMyDataToServer(serverStream, challenge);

                    challenge = ReceiveMyDataFromServer(serverStream);
                }

                // Create a secure stream
                var secureStream = new SaslStream(serverStream, new Ntlmv2Cipher(m.SessionKey));

                SendMyDataToServer(secureStream, request);
                var response = ReceiveMyDataFromServer(secureStream);
            }
        }
    }


### Features

The library supports the following authentication mechanisms:
 * Plain
 * Cram-Md5
 * NTLM
 * NTLMv2
 * OAuth
 * OAuth 2.0
 * Digest-Md5
 * Scram-Sha-1
 * SRP

Custom SASL Security Providers can be implemented through a simple plugin
mechanism.


### Credits

This library is copyright © 2013-2014 Torben Könke.



### License

This library is released under the [MIT license](https://github.com/smiley22/S22.Sasl/blob/master/License.md).


### Bug reports

Please send your bug reports to [smileytwentytwo@gmail.com](mailto:smileytwentytwo@gmail.com) or create a new
issue on the GitHub project homepage.

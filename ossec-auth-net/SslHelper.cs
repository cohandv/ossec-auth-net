using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Security.Authentication;
using System.IO;

namespace ossec_auth_net
{
    public class SslHelper
    {
        private string hostName {get;set;}
        private SslStream sslStream {get;set;}

        public SslHelper(string host, SslStream stream)
        {
            hostName = host;
            sslStream = stream;
        }

        public void ClienSideHandshake(string certpath)
        {
            Console.WriteLine("Start authentication ... ");

            X509CertificateCollection clientCertificates = new X509CertificateCollection { X509Certificate.CreateFromCertFile(Path.Combine(certpath, "certificate.cer")) };

            SslProtocols sslProtocol = SslProtocols.Tls;
            bool checkCertificateRevocation = true;

            //Start the handshake
            sslStream.AuthenticateAsClient(hostName, clientCertificates, sslProtocol, checkCertificateRevocation);

        }

        

        public static bool ServerValidationCallback(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            switch (sslPolicyErrors)
            {
                case SslPolicyErrors.RemoteCertificateNameMismatch:
                    Console.WriteLine("Server name mismatch. End communication ...\n");
                    return false;
                case SslPolicyErrors.RemoteCertificateNotAvailable:
                    Console.WriteLine("Server's certificate not available. End communication ...\n");
                    return false;
                case SslPolicyErrors.RemoteCertificateChainErrors:
                    Console.WriteLine("Server's certificate validation failed. End communication ...\n");
                    return false;
            }        //Perform others checks using the "certificate" and "chain" objects ...
            // ...
            // ...
            Console.WriteLine("Server's authentication succeeded ...\n");
            return true;
        }

        public static X509Certificate ClientCertificateSelectionCallback(object sender, string targetHost, X509CertificateCollection localCertificates, X509Certificate remoteCertificate, string[] acceptableIssuers)
        {
            //perform some checks on the certificate ...
            // ... 
            // ...
            //return the selected certificate. If null is returned, the client’s authentication does
            //not take place. 
            return localCertificates[0];
        }

        public void SendDataToServer(string message)
        {
            byte[] buffer = Encoding.UTF8.GetBytes(message);
            sslStream.Write(buffer, 0, buffer.Length);
        }
    }
}

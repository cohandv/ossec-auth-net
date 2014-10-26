using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Security.Authentication;
using System.Diagnostics;
using System.ServiceProcess;

namespace ossec_auth_net
{
    class Program
    {
        private const string OssecServiceName = "OSSEC HIDS";
        private const string OssecClientKeyFile = "client.keys";
        private const string OssecResponseTag = "OSSEC K:";

        static int Main(string[] args)
        {
            if (!args.Length.Equals(3))
            {
                Console.WriteLine("\nOSSEC HIDS: Connects to the manager to extract the agent key.\n");
                Console.WriteLine("ossec_auth_net <manager_ip> <port> <OSSEC Dir>");
                return -1;
            }

            string manager = args[0];
            int port = Convert.ToInt32(args[1]);
            string ossecInstallPath = args[2];
            string agentname = Dns.GetHostName();
            string key = string.Empty;
            Console.WriteLine("Program Started");

            RemoteCertificateValidationCallback validationCallback =
                new RemoteCertificateValidationCallback(SslHelper.ServerValidationCallback);

            LocalCertificateSelectionCallback selectionCallback =
              new LocalCertificateSelectionCallback(SslHelper.ClientCertificateSelectionCallback);

            EncryptionPolicy encryptionPolicy = EncryptionPolicy.RequireEncryption;

            try
            {
                TcpClient client = new TcpClient(manager, port);

                Console.WriteLine("Starting SSL comunication");
                using (SslStream sslStream = new System.Net.Security.SslStream(client.GetStream(), false, validationCallback, selectionCallback, encryptionPolicy))
                {
                    Console.WriteLine("Connected to manager");
                    SslHelper sslHelper = new SslHelper(manager, sslStream);

                    //1. start the authentication process. If it doesn't succeed 
                    //an AuthenticationException is thrown
                    sslHelper.ClienSideHandshake(ossecInstallPath);

                    //2. send the input message to the server
                    Console.WriteLine("Adding agent: " + agentname);
                    //sslHelper.SendDataToServer(string.Format("OSSEC A:'%0'", agentname));
                    StreamWriter writer = new StreamWriter(sslStream);
                    writer.WriteLine(string.Format("OSSEC A:'{0}'", agentname));
                    writer.Flush();


                    Console.WriteLine("Send request to manager. Waiting for reply.");

                    StreamReader reader = new StreamReader(sslStream, true);
                    string response = reader.ReadToEnd();

                    if (response.Contains(OssecResponseTag))
                    {
                        ServiceController ossecAgentService =  ServiceController.GetServices().Where(s => s.DisplayName.CompareTo(OssecServiceName).Equals(0)).FirstOrDefault();
                        if (ossecAgentService.Status != ServiceControllerStatus.Stopped)
                        {
                            ossecAgentService.Stop();
                        }

                        key = response.Replace(OssecResponseTag, string.Empty).Replace("'", string.Empty);
                        string clientKeys = Path.Combine(ossecInstallPath, OssecClientKeyFile);
                        if (File.Exists(clientKeys))
                        {
                            File.Delete(clientKeys);
                        }
                        File.WriteAllText(clientKeys, key);
                        Console.WriteLine("File saved succesfully");
                        ossecAgentService.Start();
                        Console.WriteLine("Starting agent");
                    }
                    else
                    {
                        Console.WriteLine(string.Format("Response from manager error: %0", response));
                        return -1;
                    }
                }

                Console.WriteLine("Connection closed");
                Console.WriteLine("OSSEC Agent succesfully configured!");
                return 0;

            }
            catch (Exception ex)
            {
                Console.WriteLine("Error connecting to manager: " + ex.Message);
                return -1;
            }
        }

    }
}
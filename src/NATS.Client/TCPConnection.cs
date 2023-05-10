using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices.ComTypes;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using static NATS.Client.Defaults;

namespace NATS.Client
{


    /// <summary>
    /// Convenience class representing the TCP connection to prevent 
    /// managing two variables throughout the NATs client code.
    /// </summary>

    public class TCPConnection : ITCPConnection
    {
        /// A note on the use of streams.  .NET provides a BufferedStream
        /// that can sit on top of an IO stream, in this case the network
        /// stream. It increases performance by providing an additional
        /// buffer.
        /// 
        /// So, here's what we have for writing:
        ///     Client code
        ///          ->BufferedStream (bw)
        ///              ->NetworkStream/SslStream (srvStream)
        ///                  ->TCPClient (srvClient);
        ///                  
        ///  For reading:
        ///     Client code
        ///          ->NetworkStream/SslStream (srvStream)
        ///              ->TCPClient (srvClient);
        /// 
        Connection natsConnection;

        object mu = new object();
        TcpClient client = null;
        NetworkStream stream = null;
        SslStream sslStream = null;

        string hostName = null;

        public virtual void open(Srv s, Connection connection, int timeoutMillis)
        {
            natsConnection = connection;

            lock (mu)
            {
                // If a connection was lost during a reconnect we 
                // we could have a defunct SSL stream remaining and 
                // need to clean up.
                if (sslStream != null)
                {
                    try
                    {
                        sslStream.Dispose();
                    }
                    catch (Exception) { }
                    sslStream = null;
                }

                client = new TcpClient(Socket.OSSupportsIPv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork);
                if (Socket.OSSupportsIPv6)
                    client.Client.DualMode = true;

                var task = client.ConnectAsync(s.Url.Host, s.Url.Port);
                // avoid raising TaskScheduler.UnobservedTaskException if the timeout occurs first
                task.ContinueWith(t => 
                {
                    GC.KeepAlive(t.Exception);
                    close(client);
                }, TaskContinuationOptions.OnlyOnFaulted);
                if (!task.Wait(TimeSpan.FromMilliseconds(timeoutMillis)))
                {
                    close(client);
                    client = null;
                    throw new NATSConnectionException("timeout");
                }

                client.NoDelay = false;

                client.ReceiveBufferSize = defaultBufSize * 2;
                client.SendBufferSize = defaultBufSize;

                stream = client.GetStream();

                // save off the hostname
                hostName = s.Url.Host;
            }
        }

        private static bool remoteCertificateValidation(
              object sender,
              X509Certificate certificate,
              X509Chain chain,
              SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
                return true;

            return false;
        }

        public virtual void close(TcpClient c)
        {
#if NET46
                    c?.Close();
#else
            c?.Dispose();
#endif
            c = null;
        }

        public void makeTLS()
        {
            Options options = natsConnection.Opts;

            RemoteCertificateValidationCallback cb = null;

            if (stream == null)
                throw new NATSException("public error:  Cannot create SslStream from null stream.");

            cb = options.TLSRemoteCertificationValidationCallback;
            if (cb == null)
                cb = remoteCertificateValidation;

            sslStream = new SslStream(stream, false, cb, null,
                EncryptionPolicy.RequireEncryption);

            try
            {
                SslProtocols protocol = (SslProtocols)Enum.Parse(typeof(SslProtocols), "Tls12");
                sslStream.AuthenticateAsClientAsync(hostName, options.certificates, protocol, options.CheckCertificateRevocation).Wait();
            }
            catch (Exception ex)
            {
                sslStream.Dispose();
                sslStream = null;

                close(client);
                client = null;
                throw new NATSConnectionException("TLS Authentication error", ex);
            }
        }

        public int SendTimeout
        {
            set
            {
                if (client != null)
                    client.SendTimeout = value;
            }
        }

        public int ReceiveTimeout
        {
            get
            {
                if (client == null)
                    throw new InvalidOperationException("Connection not properly initialized.");

                return client.ReceiveTimeout;
            }
            set
            {
                if (client != null)
                    client.ReceiveTimeout = value;
            }
        }

        public bool isSetup()
        {
            return (client != null);
        }

        public void teardown()
        {
            TcpClient c;
            Stream s;

            lock (mu)
            {
                c = client;
                s = getReadBufferedStream();

                client = null;
                stream = null;
                sslStream = null;
            }

            try
            {
                if (s != null)
                    s.Dispose();

                if (c != null)
                    close(c);
            }
            catch (Exception) { }
        }

        public Stream getReadBufferedStream()
        {
            if (sslStream != null)
                return sslStream;

            return stream;
        }

        public Stream getWriteBufferedStream(int size)
        {

            BufferedStream bs = null;
            if (sslStream != null)
                bs = new BufferedStream(sslStream, size);
            else
                bs = new BufferedStream(stream, size);

            return bs;
        }

        public bool Connected
        {
            get
            {
                var tmp = client;
                if (tmp == null)
                    return false;

                return tmp.Connected;
            }
        }

        public bool DataAvailable
        {
            get
            {
                var tmp = stream;
                if (tmp == null)
                    return false;

                return tmp.DataAvailable;
            }
        }

        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls

        void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (sslStream != null)
                    sslStream.Dispose();
                if (stream != null)
                    stream.Dispose();
                if (client != null)
                {
                    close(client);
                    client = null;
                }

                disposedValue = true;
            }
        }

        public void Dispose()
        {
            Dispose(true);
        }
        #endregion
    }
}

using Microsoft.VisualBasic.CompilerServices;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Security.Cryptography;
using System.Linq;

namespace SocketServer
{
    class Program
    {
        public List<TcpClient> clients = new List<TcpClient>();
        public List<byte[]> clientKey = new List<byte[]>();

        public byte[] stdKey = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
        public byte[] stdIV = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        public void Server()
        {
            //IPAddress ip = IPAddress.Parse("127.0.0.1");
            int port = 13356;
            TcpListener listener = new TcpListener(IPAddress.Any, port);
            listener.Start();
            AcceptClients(listener);
            Console.WriteLine("Server Startet!");

            bool isRunning = true;
            while (isRunning)
            {
                Console.Write("Message to client: ");
                string text = Console.ReadLine();

                //********************************* AES kryptering ********************************************
                Aes myAes = Aes.Create();
                myAes.Padding = PaddingMode.Zeros;
               
                byte[] encrypt = EncryptStringToBytes_Aes(text, stdKey, stdIV);
                string decrypt = DecryptStringFromBytes_Aes(encrypt, stdKey, stdIV);

                Console.WriteLine("Encrypted: {0}", Encoding.UTF8.GetString(encrypt));
                Console.WriteLine("Decrypted: {0}", decrypt);

                //********************************* iksf kryptering ********************************************
                //byte[] buffer = crypt(Encoding.UTF8.GetBytes(text));
                //Console.WriteLine("Encrypted: " + Encoding.UTF8.GetString(buffer));
                //Console.WriteLine("Decrypted: " + Encoding.UTF8.GetString(crypt(buffer,false)));

                byte[] buffer = encrypt;
                foreach (TcpClient foundclient in clients) 
                {
                    foundclient.GetStream().Write(encrypt, 0, encrypt.Length); 
                }
            }
        }



        public async void ReceiveMessages(NetworkStream stream)
        {
            byte[] buffer = new byte[512];
            bool isRunning = true;
            while (isRunning)
            {
                int read = await stream.ReadAsync(buffer, 0, buffer.Length);
                if (read > 0)
                {

                    string text = Encoding.UTF8.GetString(buffer, 0, read);
                    ///string decrypt = DecryptStringFromBytes_Aes(Encoding.UTF8.GetBytes(text), stdKey, stdIV);
                    string decrypt = DecryptStringFromBytes_Aes(buffer.Take(read).ToArray(), stdKey, stdIV);

                    byte[] msg = EncryptStringToBytes_Aes("tak!", stdKey, stdIV);

                    // Send back a response.
                    //stream.Write(msg, 0, msg.Length);
                    stream.Write(msg, 0, msg.Length);

                    Console.WriteLine("");
                    Console.WriteLine("Encrypted from client: " + text);
                    Console.WriteLine("Decrypted from Client: " + decrypt);
                    //Console.WriteLine("Decrypted from client: " + Encoding.UTF8.GetString(crypt(Encoding.UTF8.GetBytes(text),false)));
                    Console.Write("Message to client: ");

                }
            }
        }

        public async void AcceptClients(TcpListener listener)
        {
            bool isRunning = true;
            var rnd = new Random();
            string pkey = "666";

            while (isRunning)
            {
                TcpClient client = await listener.AcceptTcpClientAsync();
                string key = rnd.Next(10, 255).ToString();
                string commonKey = "";

                clients.Add(client);
                clientKey.Add(EncryptStringToBytes_Aes(key, stdKey, stdIV));
                NetworkStream stream = client.GetStream();

                byte[] publicKey = EncryptStringToBytes_Aes("\nPublic Key:" + pkey + "\n" + "Your Key:" + key, stdKey, stdIV);
                stream.Write(publicKey, 0, publicKey.Length);

                if (clientKey.Count > 1)
                {
                    int keyA= Int16.Parse(DecryptStringFromBytes_Aes(clientKey[0], stdKey, stdIV));
                    int keyB = Int16.Parse(DecryptStringFromBytes_Aes(clientKey[1], stdKey, stdIV));
                    Console.WriteLine("Common key:"+(keyA + keyB+666));
                }

                ReceiveMessages(stream);
            }
        }
        /*
        public byte[] crypt(byte[] text,bool type=true)
        {
            var rand = new Random();
            string cryptedText = "";
            for (int i = 0; i <text.Length; )
            {
                if (type)
                {
                    int asciiNr = Convert.ToInt32(text[i]);
                    int reverseAscii = 255 - asciiNr;
                    text[i + 3] = (byte)rand.Next(0, 2);
                    text[i] = (byte)rand.Next(0, 255);
                    text[i + 1] = (byte)rand.Next(0, 255);
                    text[i + 2] = (byte)rand.Next(0, 255);
                    text[i+text[i + 3]] = (byte)reverseAscii;
                    //cryptedText += char.ConvertFromUTF8(reverseAscii);
                    cryptedText += char.ConvertFromUTF8(text[i])+char.ConvertFromUTF8(text[i+1])+ char.ConvertFromUTF8(text[i+2])+char.ConvertFromUTF8(text[i+3]);
                    i += 4;
                }
                else
                {
                    byte[] test = text;
                    byte testA= text[i+12];
                    int charPos = text[i + 12];
                    int asciiNr = Convert.ToInt32(text[i+4*charPos]);
                    int reverseAscii = 255 - asciiNr;
                    cryptedText += char.ConvertFromUTF8(reverseAscii);
                    i += 16;
                }
            }
            return Encoding.UTF8.GetBytes(cryptedText);
        }
        */
        static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Padding = PaddingMode.Zeros;
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }

        static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Padding = PaddingMode.Zeros;
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }

        static void Main(string[] args)
        {
            Program server = new Program();
            server.Server();
        }
    }
}

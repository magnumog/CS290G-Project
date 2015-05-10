using System;
using System.IO;
using System.Security.Cryptography;

// AES modes: http://en.wikipedia.org/wiki/Block_cipher_mode_of_operation

namespace Tester
{
    class Program
    {
        static void Main(string[] args)
        {
            // read files as bytes
            var key = File.ReadAllBytes(@"..\..\..\key.txt");
            var text = File.ReadAllBytes(@"..\..\..\text.txt");

            // create cryptographic scheme (AES)
            var aes = new AesManaged
            {
                Key = key,
                KeySize = 128
            };

            // encrypt
            var memoryStream = new MemoryStream();
            using (var stream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
            {
                stream.Write(text, 0, text.Length);
            }

            var encryptedText = memoryStream.ToArray();

            // console output
            int i = 0;
            foreach (var c in encryptedText)
            {
                // index, decimal, hexadecimal, character
                Console.WriteLine("{2}\t{0:D}\t{0:X}\t{1}", c, (char)c, i);
                i++;
            }

            Console.ReadKey(true);
        }
    }
}
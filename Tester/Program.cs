using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

// AES modes: http://en.wikipedia.org/wiki/Block_cipher_mode_of_operation

namespace Tester
{
    public static class Program
    {
        public static void Main(string[] args)
        {
            // read files as bytes
            var keys = ReadFile(@"..\..\..\key.txt");
            var texts = ReadFile(@"..\..\..\text.txt");

            var key = keys.First();
            var text = texts.First();

            // create cryptographic scheme (AES)
            var aes = new AesManaged
            {
                Key = key,
                IV = key,
                Mode = CipherMode.ECB,
                Padding = PaddingMode.None
            };




            var k = aes.CreateEncryptor();

            var l = k.TransformFinalBlock(text, 0, 16);
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
                Console.WriteLine("{2}\t{0:D}\t{0:X2}\t{1}", c, (char)c, i);
                i++;
            }

            Console.ReadKey(true);
        }

        private static IEnumerable<byte[]> ReadFile(string filename)
        {
            var q = from line in File.ReadLines(filename)
                    where line.Length == 16
                    let byteArr = line.Select(c => (byte)Convert.ToInt32(c.ToString(), 16)).ToArray()
                    select byteArr;

            return q;
        }
    }
}
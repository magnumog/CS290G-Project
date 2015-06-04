using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

// AES modes: http://en.wikipedia.org/wiki/Block_cipher_mode_of_operation

namespace Tester
{
    public static class Program
    {
        private static readonly Random RandomGenerator = new Random();
        private static readonly string CharArray = "0123456789ABCDEF";

        public static void Main(string[] args)
        {
            // create messages
            var createdMessages = Enumerable.Range(0, 1000000).Select(_ => GenerateHex32());
            //File.WriteAllText("messages.txt", string.Join("\n", createdMessages));

            // read files as bytes
            var key = ReadFile(@"..\..\..\key.txt").First();
            var messages = ReadFile(@"..\..\..\messages.txt");

            // create cryptographic scheme (AES)
            var aes = new AesManaged
            {
                Key = key,
                IV = key,
                Mode = CipherMode.ECB,
                Padding = PaddingMode.None
            };
            var encryptor = aes.CreateEncryptor();

            // encrypt
            File.WriteAllText("encrypted.txt", string.Join("\n", messages.Select(m => Encrypt(encryptor, m))));
        }

        private static IEnumerable<byte[]> ReadFile(string filename)
        {
            var q = from line in File.ReadLines(filename)
                    where line.Length == 32

                    let byteArr = SplitStr2(line).Select(str2 => (byte)Convert.ToInt32(str2.ToString(), 16)).ToArray()
                    select byteArr;

            return q;
        }

        private static string GenerateHex32()
        {
            var sb = new StringBuilder(32, 32);

            for (int i = 0; i < 32; i++)
            {
                sb.Append(CharArray[RandomGenerator.Next(16)]);
            }

            return sb.ToString();
        }

        private static string Encrypt(ICryptoTransform encryptor, byte[] message)
        {
            var memoryStream = new MemoryStream();
            using (var stream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
            {
                stream.Write(message, 0, message.Length);
            }

            var encryptedText = memoryStream.ToArray();

            var sb = new StringBuilder(32, 32);
            foreach (var c in encryptedText)
            {
                sb.AppendFormat("{0:X2}", c);
            }

            return sb.ToString();
        }

        private static IEnumerable<string> SplitStr2(string str)
        {
            int i = 0;
            while (i+1 < str.Length)
            {
                yield return str.Substring(i, 2);
                i += 2;
            }
        }
    }
}
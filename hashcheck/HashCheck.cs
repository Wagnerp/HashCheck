using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace hashcheck
{
    class HashCheck
    {
        static string[] DefaultHashes = new string[]
        {
            "CRC32",
            "CRC64",
            "MD5",
            "SHA1",
            "SHA256",
            "SHA384",
            "SHA512"
        };

        static System.Security.Cryptography.HashAlgorithm CreateHashAlgorithmInstance(string hashName)
        {
            switch (hashName)
            {
                case "CRC32":
                    return new DamienG.Security.Cryptography.Crc32();

                case "CRC64":
                    return new DamienG.Security.Cryptography.Crc64Iso();

                default:
                    return System.Security.Cryptography.HashAlgorithm.Create(hashName);
            }
        }

        static void HashFile(string fileName, Dictionary<string, string> hashes)
        {
            var digesters = new Dictionary<string, System.Security.Cryptography.HashAlgorithm>();

            try
            {
                foreach (string hashName in hashes.Keys)
                {
                    digesters.Add(hashName, CreateHashAlgorithmInstance(hashName));
                }

                using (var stream = new System.IO.FileStream(fileName, System.IO.FileMode.Open, System.IO.FileAccess.Read))
                {
                    var chunk = new byte[1024];
                    int numRead = 0;

                    while (0 != (numRead = stream.Read(chunk, 0, chunk.Length)))
                    {
                        foreach (var digester in digesters.Values)
                        {
                            digester.TransformBlock(chunk, 0, numRead, chunk, 0);
                        }
                    }

                    foreach (var hash in digesters)
                    {
                        hash.Value.TransformFinalBlock(chunk, 0, 0);
                        byte[] binHash = hash.Value.Hash;
                        hashes[hash.Key] = BitConverter.ToString(binHash).Replace("-", "").ToUpper();
                    }
                }
            }
            finally
            {
                foreach (var digester in digesters.Values)
                {
                    digester.Dispose();
                }
            }
        }

        static int Main(string[] args)
        {
            if (args.Length < 1)
            {
                Usage();
                return 1;
            }

            string fileName = args[0];
            string hashName = null;
            string suppliedHash = null;

            if (args.Length > 1)
            {
                hashName = args[1].ToUpper().Replace("-", "");

                if (!DefaultHashes.Contains(hashName))
                {
                    Console.Error.WriteLine("Unrecognized hash name '{0}'", hashName);
                    Usage();
                    return 2;
                }
            }

            if (args.Length > 2)
            {
                suppliedHash = args[2].Replace("-", "").ToUpper();
            }

            if (args.Length > 3)
            {
                Usage();
                return 1;
            }

            var requiredHashes = new Dictionary<string, string>();

            if (hashName == null)
            {
                foreach (var hash in DefaultHashes)
                {
                    requiredHashes.Add(hash, null);
                }
            }
            else
            {
                requiredHashes.Add(hashName, null);
            }

            try
            {
                HashFile(fileName, requiredHashes);
            }
            catch (System.Exception ex)
            {
                Console.Error.WriteLine("Error: {0}", ex);
                return 3;
            }

            if (suppliedHash != null)
            {
                string ourHash = requiredHashes.First().Value;

                if (ourHash == suppliedHash)
                {
                    Console.WriteLine("Hashes match :-)");
                    return 0;
                }
                else
                {
                    Console.Error.WriteLine("{0} hashes do not match.", hashName);
                    Console.Error.WriteLine("Supplied hash was: {0}", suppliedHash);
                    Console.Error.WriteLine("Computed hash was: {0}", ourHash);
                    return 3;
                }
            }
            else
            {
                foreach (var hashInfo in requiredHashes)
                {
                    Console.WriteLine("{0}: {1}", hashInfo.Key, hashInfo.Value);
                }
            }

            return 0;
        }

        private static void Usage()
        {
            Console.Error.WriteLine("USAGE: HashCheck FileName [HashName [HashToCheck]]");
            Console.Error.WriteLine("Hashes the file specified by FileName");
            Console.Error.WriteLine("If HashName is supplied, that hash is used, otherwise all the known hash and CRC types will be output. Known hash/CRC types are: ");

            foreach (string hash in DefaultHashes)
            {
                Console.Error.WriteLine("\t{0}", hash);
            }

            Console.Error.WriteLine("If HashToCheck is supplied, then it must be the hex of the expected hash, and a verification of whether it matches will be output rather than the hash itself.");
        }
    }
}

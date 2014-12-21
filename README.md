HashCheck
=========

Windows command-line utility for computing and checking hashes and CRCs on a file,
for verifying downloads.

USAGE: `HashCheck FileName [HashName [HashToCheck]]`

Hashes the file specified by `FileName`

If `HashName` is supplied, that hash is used, otherwise all the known hash and CRC types will be output.

Known hash/CRC types are:
 + CRC32
 + CRC64
 + MD5
 + SHA1
 + SHA256
 + SHA384
 + SHA512

If `HashToCheck` is supplied, then it must be the hex of the expected hash, and a verification of whether it matches will be output rather than the hash itself.

See [Checking the Hash or Checksum of a Download (Softwariness.com)](https://www.softwariness.com/musings/checking-the-hash-or-checksum-of-a-download/) for more information.

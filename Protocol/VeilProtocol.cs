using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace VeilDesktop.Protocol;

public sealed class VeilKeySet
{
    public string Ed25519Pub { get; set; } = "";
    public string Ed25519Priv { get; set; } = "";
    public string MlDsaPub { get; set; } = "";
    public string MlDsaPriv { get; set; } = "";
    public string X25519Pub { get; set; } = "";
    public string X25519Priv { get; set; } = "";
    public string MlKemPub { get; set; } = "";
    public string MlKemPriv { get; set; } = "";
}

public sealed class VeilIdentity
{
    public string Protocol { get; set; } = VeilProtocol.ProtocolName;
    public string DisplayName { get; set; } = "";
    public string CreatedAt { get; set; } = "";
    public string FingerprintHex { get; set; } = "";
    public string ShortId { get; set; } = "";
    public string SafetyPhrase { get; set; } = "";
    public VeilKeySet Keys { get; set; } = new();

    public bool IsFullPostQuantum => !string.IsNullOrEmpty(Keys.MlDsaPub) && !string.IsNullOrEmpty(Keys.MlDsaPriv);
    public string SwitcherLabel => $"{DisplayName} [{ShortId}] ({SafetyPhrase})";
}

public sealed class VeilContactCard
{
    public string DisplayName { get; set; } = "";
    public string FingerprintHex { get; set; } = "";
    public string ShortId { get; set; } = "";
    public string SafetyPhrase { get; set; } = "";
    public string CardBase64 { get; set; } = "";
    public string Uri { get; set; } = "";
    public byte[] CardBytes { get; set; } = Array.Empty<byte>();
    public string Ed25519Pub { get; set; } = "";
    public string MlDsaPub { get; set; } = "";
    public string X25519Pub { get; set; } = "";
    public string MlKemPub { get; set; } = "";
    public bool IsFullPostQuantum => !string.IsNullOrEmpty(MlDsaPub);
}

public sealed class VeilAttachment
{
    public string Name { get; set; } = "";
    public string Mime { get; set; } = "application/octet-stream";
    public int Size { get; set; }
    public string DataBase64 { get; set; } = "";
}

public sealed class SealedResult
{
    public byte[] PacketBytes { get; set; } = Array.Empty<byte>();
    public string TranscriptHashHex { get; set; } = "";
    public int PaddedInnerBytes { get; set; }
    public string SentAt { get; set; } = "";
}

public sealed class OpenedEnvelope
{
    public bool Verified { get; set; }
    public bool PostQuantumSignatureVerified { get; set; }
    public bool IsPassphraseMode { get; set; }
    public string SentAt { get; set; } = "";
    public string Message { get; set; } = "";
    public VeilAttachment? Attachment { get; set; }
    public VeilContactCard Sender { get; set; } = new();
    public string TranscriptHashHex { get; set; } = "";
    public int TotalPacketBytes { get; set; }
    public int PaddedPlaintextBytes { get; set; }
}

public sealed class PacketSegment
{
    public int Offset { get; set; }
    public int Length { get; set; }
    public string Name { get; set; } = "";
    public string HexPreview { get; set; } = "";
    public string Role { get; set; } = "";
}

public sealed class PacketInspection
{
    public string Protocol { get; set; } = VeilProtocol.ProtocolName;
    public int TotalBytes { get; set; }
    public string TranscriptHashHex { get; set; } = "";
    public Dictionary<string, string> VisibleOnWire { get; set; } = new();
    public List<PacketSegment> Segments { get; set; } = new();
}

public static class VeilProtocol
{
    public const string ProtocolName = "VEIL-2 (Full PQ-Hybrid)";
    public const int ProtocolVersion = 2;
    public const int OuterHeaderLen = 6 + 1 + 32 + 1088 + 12;
    private const int GcmTagLen = 16;
    private const int MinBucketSize = 512;

    private static readonly byte[] EnvelopeMagicV1 = { 0x56, 0x45, 0x49, 0x4C, 0x31, 0x01 };
    private static readonly byte[] EnvelopeMagicV2 = { 0x56, 0x45, 0x49, 0x4C, 0x32, 0x02 };
    private static readonly byte[] EnvelopeMagicPassV2 = { 0x56, 0x45, 0x49, 0x4C, 0x50, 0x02 };
    private const int PassHeaderLen = 6 + 1 + 16 + 12;

    private static readonly byte[] CardMagicV1 = Encoding.ASCII.GetBytes("VCARD1");
    private static readonly byte[] CardMagicV2 = Encoding.ASCII.GetBytes("VCARD2");

    private static readonly byte[] VaultMagicV1 = { 0x56, 0x56, 0x41, 0x55, 0x4C, 0x54, 0x31, 0x01 };
    private static readonly byte[] VaultMagicV2 = { 0x56, 0x56, 0x41, 0x55, 0x4C, 0x54, 0x32, 0x02 };

    private static readonly byte[] PrivKeyMagicV1 = { 0x56, 0x4B, 0x45, 0x59, 0x31, 0x01 };
    private static readonly byte[] PrivKeyMagicV2 = { 0x56, 0x4B, 0x45, 0x59, 0x32, 0x02 };

    private static readonly SecureRandom BcRandom = new();

    private static readonly string[] Wordlist =
    {
        "acorn","agate","alder","amber","anchor","anise","anvil","apex","apricot","arch",
        "argon","arrow","aspen","aster","atlas","aurora","autumn","avocado","axis","azure",
        "badger","bamboo","banyan","basalt","beacon","birch","bison","blaze","bloom","bolt",
        "bonsai","boulder","breeze","bridge","brine","bronze","brook","canyon","carbon","cedar",
        "celeste","chalice","cinder","cipher","citrine","cliff","clover","cobalt","comet","compass",
        "copper","coral","corona","cosmos","crane","creek","crest","crimson","crown","crystal",
        "cypress","dagger","dawn","delta","desert","dewdrop","diamond","dolphin","dragon","drift",
        "dune","dusk","eagle","earth","echo","eclipse","eddy","elder","elm","ember",
        "emerald","epoch","equinox","ermine","estuary","ether","falcon","fathom","feather","fennel",
        "fern","fiddle","finch","fjord","flame","flint","flora","flute","forest","forge",
        "fossil","fox","frost","galaxy","garnet","geyser","glacier","glade","gleam","glint",
        "globe","granite","grove","harbor","harvest","haven","hawk","hazel","hearth","heather",
        "helix","heron","horizon","icicle","indigo","inlet","iris","iron","island","ivory",
        "jade","jaguar","jasper","juniper","kelp","kestrel","kettle","keystone","kindle","lagoon",
        "lantern","larch","lark","laurel","lava","leaf","ledge","lichen","lilac","linden",
        "lotus","lunar","lynx","magnet","magpie","maple","marble","marsh","meadow","mercury",
        "mesa","meteor","mica","mint","mirage","mist","monarch","moon","moss","mountain",
        "mulberry","nebula","nectar","needle","nettle","nimbus","north","nova","nutmeg","oak",
        "oasis","obsidian","ocean","ochre","olive","onyx","opal","orbit","orchid","oriole",
        "osprey","otter","owl","palm","panther","papaya","pebble","pelican","peony","pepper",
        "petal","phantom","phoenix","pine","planet","plover","plume","polar","poplar","prairie",
        "prism","pulse","puma","quartz","quasar","quiver","radian","rain","raven","reef",
        "ridge","river","robin","rowan","ruby","saffron","sage","salmon","sand","sapphire",
        "saturn","scarlet","sequoia","shadow","shale","shell","sierra","silver","slate","solar",
        "solstice","sparrow","specter","spruce","star","stone","storm","summit","sun","zephyr"
    };

    private static byte[] Sha256Concat(params byte[][] parts)
    {
        using var inc = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var p in parts) inc.AppendData(p);
        return inc.GetHashAndReset();
    }

    private static byte[] ComputeFingerprintV1(byte[] edPub, byte[] xPub, byte[] pqPub) =>
        Sha256Concat(Encoding.UTF8.GetBytes("VEIL-1-ID"), edPub, xPub, pqPub);

    private static byte[] ComputeFingerprintV2(byte[] edPub, byte[] mlDsaPub, byte[] xPub, byte[] mlKemPub) =>
        Sha256Concat(Encoding.UTF8.GetBytes("VEIL-2-ID"), edPub, mlDsaPub, xPub, mlKemPub);

    private static string ToSafetyPhrase(byte[] fp) =>
        $"{Wordlist[fp[0]]}-{Wordlist[fp[1]]}-{Wordlist[fp[2]]}-{Wordlist[fp[3]]}";

    private static string ToShortId(byte[] fp) =>
        Convert.ToHexString(fp.AsSpan(0, 8));

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=');

    private static byte[] Base64UrlDecode(string text)
    {
        string s = text.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4)
        {
            case 2: s += "=="; break;
            case 3: s += "="; break;
        }
        return Convert.FromBase64String(s);
    }

    private static byte[] DeriveArgon2idKey(string passphrase, byte[] salt)
    {
        byte[] passBytes = Encoding.UTF8.GetBytes(passphrase);
        try
        {
            var parameters = new Argon2Parameters.Builder(Argon2Parameters.Argon2id)
                .WithSalt(salt)
                .WithMemoryAsKB(65536)
                .WithIterations(3)
                .WithParallelism(2)
                .Build();
            var gen = new Argon2BytesGenerator();
            gen.Init(parameters);
            byte[] key = new byte[32];
            gen.GenerateBytes(passBytes, key);
            return key;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passBytes);
        }
    }

    public static VeilIdentity GenerateIdentity(string displayName)
    {
        string cleanName = string.IsNullOrWhiteSpace(displayName) ? "Anonymous" : displayName.Trim();
        if (cleanName.Length > 64) cleanName = cleanName[..64];

        var edGen = new Ed25519KeyPairGenerator();
        edGen.Init(new Ed25519KeyGenerationParameters(BcRandom));
        var edPair = edGen.GenerateKeyPair();
        byte[] edPriv = ((Ed25519PrivateKeyParameters)edPair.Private).GetEncoded();
        byte[] edPub = ((Ed25519PublicKeyParameters)edPair.Public).GetEncoded();

        var dsaGen = new MLDsaKeyPairGenerator();
        dsaGen.Init(new MLDsaKeyGenerationParameters(BcRandom, MLDsaParameters.ml_dsa_65));
        var dsaPair = dsaGen.GenerateKeyPair();
        byte[] dsaPriv = ((MLDsaPrivateKeyParameters)dsaPair.Private).GetEncoded();
        byte[] dsaPub = ((MLDsaPublicKeyParameters)dsaPair.Public).GetEncoded();

        var xGen = new X25519KeyPairGenerator();
        xGen.Init(new X25519KeyGenerationParameters(BcRandom));
        var xPair = xGen.GenerateKeyPair();
        byte[] xPriv = ((X25519PrivateKeyParameters)xPair.Private).GetEncoded();
        byte[] xPub = ((X25519PublicKeyParameters)xPair.Public).GetEncoded();

        var kemGen = new MLKemKeyPairGenerator();
        kemGen.Init(new MLKemKeyGenerationParameters(BcRandom, MLKemParameters.ml_kem_768));
        var kemPair = kemGen.GenerateKeyPair();
        byte[] kemPub = ((MLKemPublicKeyParameters)kemPair.Public).GetEncoded();
        byte[] kemPriv = ((MLKemPrivateKeyParameters)kemPair.Private).GetEncoded();

        byte[] fp = ComputeFingerprintV2(edPub, dsaPub, xPub, kemPub);

        var identity = new VeilIdentity
        {
            Protocol = ProtocolName,
            DisplayName = cleanName,
            CreatedAt = DateTime.UtcNow.ToString("O"),
            FingerprintHex = Convert.ToHexString(fp).ToLowerInvariant(),
            ShortId = ToShortId(fp),
            SafetyPhrase = ToSafetyPhrase(fp),
            Keys = new VeilKeySet
            {
                Ed25519Pub = Convert.ToBase64String(edPub),
                Ed25519Priv = Convert.ToBase64String(edPriv),
                MlDsaPub = Convert.ToBase64String(dsaPub),
                MlDsaPriv = Convert.ToBase64String(dsaPriv),
                X25519Pub = Convert.ToBase64String(xPub),
                X25519Priv = Convert.ToBase64String(xPriv),
                MlKemPub = Convert.ToBase64String(kemPub),
                MlKemPriv = Convert.ToBase64String(kemPriv),
            }
        };

        CryptographicOperations.ZeroMemory(edPriv);
        CryptographicOperations.ZeroMemory(dsaPriv);
        CryptographicOperations.ZeroMemory(xPriv);
        CryptographicOperations.ZeroMemory(kemPriv);
        return identity;
    }

    public static VeilContactCard ExportContactCard(VeilIdentity id)
    {
        byte[] edPub = Convert.FromBase64String(id.Keys.Ed25519Pub);
        byte[] edPriv = Convert.FromBase64String(id.Keys.Ed25519Priv);
        byte[] xPub = Convert.FromBase64String(id.Keys.X25519Pub);
        byte[] kemPub = Convert.FromBase64String(id.Keys.MlKemPub);
        byte[] nameBytes = Encoding.UTF8.GetBytes(id.DisplayName);

        try
        {
            if (id.IsFullPostQuantum)
            {
                byte[] dsaPub = Convert.FromBase64String(id.Keys.MlDsaPub);
                byte[] dsaPriv = Convert.FromBase64String(id.Keys.MlDsaPriv);
                try
                {
                    using var ms = new MemoryStream();
                    ms.Write(CardMagicV2);
                    ms.Write(edPub);
                    ms.Write(xPub);
                    ms.Write(kemPub);
                    WriteUInt16BE(ms, dsaPub.Length);
                    ms.Write(dsaPub);
                    WriteUInt16BE(ms, nameBytes.Length);
                    ms.Write(nameBytes);

                    byte[] body = ms.ToArray();
                    byte[] digest = Sha256Concat(Encoding.UTF8.GetBytes("VEIL-2-CARD"), body);

                    var edSigner = new Ed25519Signer();
                    edSigner.Init(true, new Ed25519PrivateKeyParameters(edPriv, 0));
                    edSigner.BlockUpdate(digest, 0, digest.Length);
                    byte[] edSig = edSigner.GenerateSignature();

                    var dsaSigner = new MLDsaSigner(MLDsaParameters.ml_dsa_65, deterministic: false);
                    dsaSigner.Init(true, new ParametersWithRandom(
                        MLDsaPrivateKeyParameters.FromEncoding(MLDsaParameters.ml_dsa_65, dsaPriv), BcRandom));
                    dsaSigner.BlockUpdate(digest, 0, digest.Length);
                    byte[] dsaSig = dsaSigner.GenerateSignature();

                    ms.Write(edSig);
                    WriteUInt16BE(ms, dsaSig.Length);
                    ms.Write(dsaSig);

                    byte[] cardBytes = ms.ToArray();
                    return new VeilContactCard
                    {
                        DisplayName = id.DisplayName,
                        FingerprintHex = id.FingerprintHex,
                        ShortId = id.ShortId,
                        SafetyPhrase = id.SafetyPhrase,
                        CardBytes = cardBytes,
                        CardBase64 = Convert.ToBase64String(cardBytes),
                        Uri = "veilpub2:" + Base64UrlEncode(cardBytes),
                        Ed25519Pub = id.Keys.Ed25519Pub,
                        MlDsaPub = id.Keys.MlDsaPub,
                        X25519Pub = id.Keys.X25519Pub,
                        MlKemPub = id.Keys.MlKemPub,
                    };
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(dsaPriv);
                }
            }
            else
            {

                using var ms = new MemoryStream();
                ms.Write(CardMagicV1);
                ms.Write(edPub);
                ms.Write(xPub);
                ms.Write(kemPub);
                WriteUInt16BE(ms, nameBytes.Length);
                ms.Write(nameBytes);

                byte[] body = ms.ToArray();
                byte[] digest = Sha256Concat(Encoding.UTF8.GetBytes("VEIL-1-CARD"), body);

                var edSigner = new Ed25519Signer();
                edSigner.Init(true, new Ed25519PrivateKeyParameters(edPriv, 0));
                edSigner.BlockUpdate(digest, 0, digest.Length);
                byte[] sig = edSigner.GenerateSignature();

                ms.Write(sig);
                byte[] cardBytes = ms.ToArray();
                return new VeilContactCard
                {
                    DisplayName = id.DisplayName,
                    FingerprintHex = id.FingerprintHex,
                    ShortId = id.ShortId,
                    SafetyPhrase = id.SafetyPhrase,
                    CardBytes = cardBytes,
                    CardBase64 = Convert.ToBase64String(cardBytes),
                    Uri = "veilpub1:" + Base64UrlEncode(cardBytes),
                    Ed25519Pub = id.Keys.Ed25519Pub,
                    X25519Pub = id.Keys.X25519Pub,
                    MlKemPub = id.Keys.MlKemPub,
                };
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(edPriv);
        }
    }

    private static void WriteUInt16BE(Stream s, int val)
    {
        s.WriteByte((byte)(val >> 8));
        s.WriteByte((byte)(val & 0xFF));
    }

    private static int ReadUInt16BE(byte[] buf, ref int offset)
    {
        int v = (buf[offset] << 8) | buf[offset + 1];
        offset += 2;
        return v;
    }

    public static VeilContactCard ParseContactCard(string text)
    {
        string trimmed = text.Trim();
        byte[] bytes;
        if (trimmed.StartsWith("veilpub2:", StringComparison.OrdinalIgnoreCase))
            bytes = Base64UrlDecode(trimmed["veilpub2:".Length..]);
        else if (trimmed.StartsWith("veilpub1:", StringComparison.OrdinalIgnoreCase))
            bytes = Base64UrlDecode(trimmed["veilpub1:".Length..]);
        else if (trimmed.StartsWith("veil://card/", StringComparison.OrdinalIgnoreCase))
            bytes = Base64UrlDecode(trimmed["veil://card/".Length..]);
        else
            bytes = Convert.FromBase64String(trimmed);
        return ParseContactCard(bytes);
    }

    public static VeilContactCard ParseContactCard(byte[] buf)
    {
        if (buf.Length < 10) throw new InvalidDataException("Contact public key is truncated.");

        if (buf.AsSpan(0, 6).SequenceEqual(CardMagicV2))
            return ParseContactCardV2(buf);

        if (buf.AsSpan(0, 6).SequenceEqual(CardMagicV1))
            return ParseContactCardV1(buf);

        throw new InvalidDataException("Unrecognized Veil public key format (expected VCARD2 or VCARD1).");
    }

    private static VeilContactCard ParseContactCardV2(byte[] buf)
    {
        int offset = 6;
        byte[] edPub = buf[offset..(offset + 32)]; offset += 32;
        byte[] xPub = buf[offset..(offset + 32)]; offset += 32;
        byte[] kemPub = buf[offset..(offset + 1184)]; offset += 1184;
        int dsaPubLen = ReadUInt16BE(buf, ref offset);
        byte[] dsaPub = buf[offset..(offset + dsaPubLen)]; offset += dsaPubLen;
        int nameLen = ReadUInt16BE(buf, ref offset);
        string name = Encoding.UTF8.GetString(buf, offset, nameLen); offset += nameLen;

        int bodyEnd = offset;
        byte[] edSig = buf[offset..(offset + 64)]; offset += 64;
        int dsaSigLen = ReadUInt16BE(buf, ref offset);
        byte[] dsaSig = buf[offset..(offset + dsaSigLen)]; offset += dsaSigLen;

        if (offset != buf.Length)
            throw new InvalidDataException("Public key length mismatch.");

        byte[] digest = Sha256Concat(Encoding.UTF8.GetBytes("VEIL-2-CARD"), buf[..bodyEnd]);

        var edVerifier = new Ed25519Signer();
        edVerifier.Init(false, new Ed25519PublicKeyParameters(edPub, 0));
        edVerifier.BlockUpdate(digest, 0, digest.Length);
        if (!edVerifier.VerifySignature(edSig))
            throw new CryptographicException("Public key Ed25519 self-signature verification failed.");

        var dsaVerifier = new MLDsaSigner(MLDsaParameters.ml_dsa_65, deterministic: false);
        dsaVerifier.Init(false, MLDsaPublicKeyParameters.FromEncoding(MLDsaParameters.ml_dsa_65, dsaPub));
        dsaVerifier.BlockUpdate(digest, 0, digest.Length);
        if (!dsaVerifier.VerifySignature(dsaSig))
            throw new CryptographicException("Public key ML-DSA-65 post-quantum self-signature verification failed.");

        byte[] fp = ComputeFingerprintV2(edPub, dsaPub, xPub, kemPub);
        return new VeilContactCard
        {
            DisplayName = name,
            FingerprintHex = Convert.ToHexString(fp).ToLowerInvariant(),
            ShortId = ToShortId(fp),
            SafetyPhrase = ToSafetyPhrase(fp),
            CardBytes = buf,
            CardBase64 = Convert.ToBase64String(buf),
            Uri = "veilpub2:" + Base64UrlEncode(buf),
            Ed25519Pub = Convert.ToBase64String(edPub),
            MlDsaPub = Convert.ToBase64String(dsaPub),
            X25519Pub = Convert.ToBase64String(xPub),
            MlKemPub = Convert.ToBase64String(kemPub),
        };
    }

    private static VeilContactCard ParseContactCardV1(byte[] buf)
    {
        int offset = 6;
        byte[] edPub = buf[offset..(offset + 32)]; offset += 32;
        byte[] xPub = buf[offset..(offset + 32)]; offset += 32;
        byte[] kemPub = buf[offset..(offset + 1184)]; offset += 1184;
        int nameLen = ReadUInt16BE(buf, ref offset);
        if (buf.Length != offset + nameLen + 64)
            throw new InvalidDataException("Contact card length mismatch.");

        string name = Encoding.UTF8.GetString(buf, offset, nameLen); offset += nameLen;
        byte[] sig = buf[offset..(offset + 64)];

        byte[] digest = Sha256Concat(Encoding.UTF8.GetBytes("VEIL-1-CARD"), buf[..^64]);
        var verifier = new Ed25519Signer();
        verifier.Init(false, new Ed25519PublicKeyParameters(edPub, 0));
        verifier.BlockUpdate(digest, 0, digest.Length);
        if (!verifier.VerifySignature(sig))
            throw new CryptographicException("Contact card Ed25519 self-signature verification failed.");

        byte[] fp = ComputeFingerprintV1(edPub, xPub, kemPub);
        return new VeilContactCard
        {
            DisplayName = name,
            FingerprintHex = Convert.ToHexString(fp).ToLowerInvariant(),
            ShortId = ToShortId(fp),
            SafetyPhrase = ToSafetyPhrase(fp),
            CardBytes = buf,
            CardBase64 = Convert.ToBase64String(buf),
            Uri = "veilpub1:" + Base64UrlEncode(buf),
            Ed25519Pub = Convert.ToBase64String(edPub),
            X25519Pub = Convert.ToBase64String(xPub),
            MlKemPub = Convert.ToBase64String(kemPub),
        };
    }

    private static byte[] PadPlaintext(byte[] payload)
    {
        int needed = 4 + payload.Length;
        int bucket = MinBucketSize;
        while (bucket < needed) bucket *= 2;

        byte[] padded = new byte[bucket];
        padded[0] = (byte)(payload.Length >> 24);
        padded[1] = (byte)(payload.Length >> 16);
        padded[2] = (byte)(payload.Length >> 8);
        padded[3] = (byte)(payload.Length & 0xFF);
        Buffer.BlockCopy(payload, 0, padded, 4, payload.Length);
        if (bucket > needed)
            RandomNumberGenerator.Fill(padded.AsSpan(needed, bucket - needed));
        return padded;
    }

    private static byte[] UnpadPlaintext(byte[] padded)
    {
        if (padded.Length < 4) throw new InvalidDataException("Corrupt padded payload.");
        int len = (padded[0] << 24) | (padded[1] << 16) | (padded[2] << 8) | padded[3];
        if (len < 0 || 4 + len > padded.Length) throw new InvalidDataException("Corrupt payload length.");
        return padded[4..(4 + len)];
    }

    private static (byte[] SessionKey, byte[] TranscriptHash) DeriveHybridSessionKey(
        byte[] ssEcdh, byte[] ssPq, byte[] ephemXPub, byte[] recipientXPub, byte[] outerHeader, bool isV2)
    {
        byte[] transcriptHash = SHA256.HashData(outerHeader);
        byte[] ikm = new byte[ssEcdh.Length + ssPq.Length + ephemXPub.Length + recipientXPub.Length];
        try
        {
            int o = 0;
            Buffer.BlockCopy(ssEcdh, 0, ikm, o, ssEcdh.Length); o += ssEcdh.Length;
            Buffer.BlockCopy(ssPq, 0, ikm, o, ssPq.Length); o += ssPq.Length;
            Buffer.BlockCopy(ephemXPub, 0, ikm, o, ephemXPub.Length); o += ephemXPub.Length;
            Buffer.BlockCopy(recipientXPub, 0, ikm, o, recipientXPub.Length);

            string infoStr = isV2 ? "VEIL-2-HYBRID-AEAD-KEY" : "VEIL-1-HYBRID-AEAD-KEY";
            byte[] key = HKDF.DeriveKey(
                HashAlgorithmName.SHA256,
                ikm,
                32,
                salt: transcriptHash,
                info: Encoding.UTF8.GetBytes(infoStr));

            return (key, transcriptHash);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ikm);
        }
    }

    private sealed class InnerPayloadDto
    {
        public int v { get; set; } = ProtocolVersion;
        public string sentAt { get; set; } = "";
        public string senderCard { get; set; } = "";
        public string message { get; set; } = "";
        public VeilAttachment? attachment { get; set; }
    }

    private sealed class SignedInnerDto
    {
        public string payload { get; set; } = "";
        public string signature { get; set; } = "";
        public string? mlDsaSignature { get; set; }
    }

    public static SealedResult SealEnvelope(
        VeilIdentity senderIdentity,
        VeilContactCard recipientCard,
        string message,
        VeilAttachment? attachment = null)
    {
        bool isV2 = senderIdentity.IsFullPostQuantum;
        byte[] recipientXPub = Convert.FromBase64String(recipientCard.X25519Pub);
        byte[] recipientPqPub = Convert.FromBase64String(recipientCard.MlKemPub);
        byte[] recipientFp = Convert.FromHexString(recipientCard.FingerprintHex);

        var senderCard = ExportContactCard(senderIdentity);
        byte[] senderEdPriv = Convert.FromBase64String(senderIdentity.Keys.Ed25519Priv);
        byte[]? senderDsaPriv = isV2 ? Convert.FromBase64String(senderIdentity.Keys.MlDsaPriv) : null;

        byte[]? ssEcdh = null;
        byte[]? ssPq = null;
        byte[]? sessionKey = null;

        try
        {
            string sentAt = DateTime.UtcNow.ToString("O");
            var inner = new InnerPayloadDto
            {
                v = isV2 ? 2 : 1,
                sentAt = sentAt,
                senderCard = senderCard.CardBase64,
                message = message ?? "",
                attachment = attachment,
            };

            byte[] payloadBytes = JsonSerializer.SerializeToUtf8Bytes(inner);
            byte[] sigInput = Sha256Concat(
                Encoding.UTF8.GetBytes(isV2 ? "VEIL-2-MSG-SIG" : "VEIL-1-MSG-SIG"),
                recipientFp,
                payloadBytes);

            var edSigner = new Ed25519Signer();
            edSigner.Init(true, new Ed25519PrivateKeyParameters(senderEdPriv, 0));
            edSigner.BlockUpdate(sigInput, 0, sigInput.Length);
            byte[] edSig = edSigner.GenerateSignature();

            string? mlDsaSigB64 = null;
            if (isV2 && senderDsaPriv != null)
            {
                var dsaSigner = new MLDsaSigner(MLDsaParameters.ml_dsa_65, deterministic: false);
                dsaSigner.Init(true, new ParametersWithRandom(
                    MLDsaPrivateKeyParameters.FromEncoding(MLDsaParameters.ml_dsa_65, senderDsaPriv), BcRandom));
                dsaSigner.BlockUpdate(sigInput, 0, sigInput.Length);
                mlDsaSigB64 = Convert.ToBase64String(dsaSigner.GenerateSignature());
            }

            byte[] signedInnerBytes = JsonSerializer.SerializeToUtf8Bytes(new SignedInnerDto
            {
                payload = Convert.ToBase64String(payloadBytes),
                signature = Convert.ToBase64String(edSig),
                mlDsaSignature = mlDsaSigB64,
            });

            byte[] paddedInner = PadPlaintext(signedInnerBytes);

            var xGen = new X25519KeyPairGenerator();
            xGen.Init(new X25519KeyGenerationParameters(BcRandom));
            var ephemPair = xGen.GenerateKeyPair();
            byte[] ephemXPub = ((X25519PublicKeyParameters)ephemPair.Public).GetEncoded();

            var agreement = new X25519Agreement();
            agreement.Init(ephemPair.Private);
            ssEcdh = new byte[agreement.AgreementSize];
            agreement.CalculateAgreement(new X25519PublicKeyParameters(recipientXPub, 0), ssEcdh, 0);

            var pqPubParams = MLKemPublicKeyParameters.FromEncoding(MLKemParameters.ml_kem_768, recipientPqPub);
            var encapsulator = new MLKemEncapsulator(MLKemParameters.ml_kem_768);
            encapsulator.Init(new ParametersWithRandom(pqPubParams, BcRandom));
            byte[] pqCt = new byte[encapsulator.EncapsulationLength];
            ssPq = new byte[encapsulator.SecretLength];
            encapsulator.Encapsulate(pqCt, 0, pqCt.Length, ssPq, 0, ssPq.Length);

            byte[] nonce = RandomNumberGenerator.GetBytes(12);
            byte flags = (byte)(0x01 | (attachment != null ? 0x02 : 0x00) | (isV2 ? 0x04 : 0x00));

            byte[] outerHeader = new byte[OuterHeaderLen];
            int o = 0;
            Buffer.BlockCopy(isV2 ? EnvelopeMagicV2 : EnvelopeMagicV1, 0, outerHeader, o, 6); o += 6;
            outerHeader[o++] = flags;
            Buffer.BlockCopy(ephemXPub, 0, outerHeader, o, 32); o += 32;
            Buffer.BlockCopy(pqCt, 0, outerHeader, o, 1088); o += 1088;
            Buffer.BlockCopy(nonce, 0, outerHeader, o, 12);

            (sessionKey, byte[] transcriptHash) = DeriveHybridSessionKey(
                ssEcdh, ssPq, ephemXPub, recipientXPub, outerHeader, isV2);

            byte[] ciphertext = new byte[paddedInner.Length];
            byte[] tag = new byte[GcmTagLen];
            using (var gcm = new AesGcm(sessionKey, GcmTagLen))
            {
                gcm.Encrypt(nonce, paddedInner, ciphertext, tag, outerHeader);
            }

            byte[] packet = new byte[OuterHeaderLen + ciphertext.Length + GcmTagLen];
            Buffer.BlockCopy(outerHeader, 0, packet, 0, OuterHeaderLen);
            Buffer.BlockCopy(ciphertext, 0, packet, OuterHeaderLen, ciphertext.Length);
            Buffer.BlockCopy(tag, 0, packet, OuterHeaderLen + ciphertext.Length, GcmTagLen);

            return new SealedResult
            {
                PacketBytes = packet,
                TranscriptHashHex = Convert.ToHexString(transcriptHash).ToLowerInvariant(),
                PaddedInnerBytes = paddedInner.Length,
                SentAt = sentAt,
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(senderEdPriv);
            if (senderDsaPriv != null) CryptographicOperations.ZeroMemory(senderDsaPriv);
            if (ssEcdh != null) CryptographicOperations.ZeroMemory(ssEcdh);
            if (ssPq != null) CryptographicOperations.ZeroMemory(ssPq);
            if (sessionKey != null) CryptographicOperations.ZeroMemory(sessionKey);
        }
    }

    public static OpenedEnvelope OpenEnvelope(VeilIdentity recipientIdentity, byte[] packetBytes)
    {
        if (packetBytes.Length < OuterHeaderLen + GcmTagLen + 4)
            throw new InvalidDataException("Invalid Veil packet: too short.");

        bool isV2;
        if (packetBytes.AsSpan(0, 6).SequenceEqual(EnvelopeMagicV2)) isV2 = true;
        else if (packetBytes.AsSpan(0, 6).SequenceEqual(EnvelopeMagicV1)) isV2 = false;
        else throw new InvalidDataException("Invalid Veil packet: unrecognized magic.");

        byte[] outerHeader = packetBytes[..OuterHeaderLen];
        byte[] ephemXPub = packetBytes[7..39];
        byte[] pqCt = packetBytes[39..1127];
        byte[] nonce = packetBytes[1127..1139];
        byte[] ciphertext = packetBytes[OuterHeaderLen..^GcmTagLen];
        byte[] tag = packetBytes[^GcmTagLen..];

        byte[] recipientXPriv = Convert.FromBase64String(recipientIdentity.Keys.X25519Priv);
        byte[] recipientXPub = Convert.FromBase64String(recipientIdentity.Keys.X25519Pub);
        byte[] recipientPqPriv = Convert.FromBase64String(recipientIdentity.Keys.MlKemPriv);
        byte[] recipientFp = Convert.FromHexString(recipientIdentity.FingerprintHex);

        byte[]? ssEcdh = null;
        byte[]? ssPq = null;
        byte[]? sessionKey = null;

        try
        {
            var agreement = new X25519Agreement();
            agreement.Init(new X25519PrivateKeyParameters(recipientXPriv, 0));
            ssEcdh = new byte[agreement.AgreementSize];
            agreement.CalculateAgreement(new X25519PublicKeyParameters(ephemXPub, 0), ssEcdh, 0);

            var pqPrivParams = MLKemPrivateKeyParameters.FromEncoding(MLKemParameters.ml_kem_768, recipientPqPriv);
            var decapsulator = new MLKemDecapsulator(MLKemParameters.ml_kem_768);
            decapsulator.Init(pqPrivParams);
            ssPq = new byte[decapsulator.SecretLength];
            decapsulator.Decapsulate(pqCt, 0, pqCt.Length, ssPq, 0, ssPq.Length);

            (sessionKey, byte[] transcriptHash) = DeriveHybridSessionKey(
                ssEcdh, ssPq, ephemXPub, recipientXPub, outerHeader, isV2);

            byte[] paddedInner = new byte[ciphertext.Length];
            try
            {
                using var gcm = new AesGcm(sessionKey, GcmTagLen);
                gcm.Decrypt(nonce, ciphertext, tag, paddedInner, outerHeader);
            }
            catch
            {
                throw new CryptographicException("Decryption failed: packet is not addressed to your active key set or was tampered with.");
            }

            byte[] signedInnerBytes = UnpadPlaintext(paddedInner);
            var signedInner = JsonSerializer.Deserialize<SignedInnerDto>(signedInnerBytes)
                ?? throw new InvalidDataException("Corrupt inner envelope.");

            byte[] payloadBytes = Convert.FromBase64String(signedInner.payload);
            byte[] edSig = Convert.FromBase64String(signedInner.signature);
            var inner = JsonSerializer.Deserialize<InnerPayloadDto>(payloadBytes)
                ?? throw new InvalidDataException("Corrupt inner payload.");

            var senderCard = ParseContactCard(inner.senderCard);
            byte[] senderEdPub = Convert.FromBase64String(senderCard.Ed25519Pub);
            byte[] sigInput = Sha256Concat(
                Encoding.UTF8.GetBytes(isV2 ? "VEIL-2-MSG-SIG" : "VEIL-1-MSG-SIG"),
                recipientFp,
                payloadBytes);

            var edVerifier = new Ed25519Signer();
            edVerifier.Init(false, new Ed25519PublicKeyParameters(senderEdPub, 0));
            edVerifier.BlockUpdate(sigInput, 0, sigInput.Length);
            if (!edVerifier.VerifySignature(edSig))
                throw new CryptographicException("Ed25519 signature invalid or message was forwarded from another recipient.");

            bool pqSigVerified = false;
            if (isV2)
            {
                if (string.IsNullOrEmpty(signedInner.mlDsaSignature) || string.IsNullOrEmpty(senderCard.MlDsaPub))
                    throw new CryptographicException("VEIL-2 envelope missing mandatory ML-DSA-65 post-quantum signature.");

                byte[] dsaSig = Convert.FromBase64String(signedInner.mlDsaSignature);
                byte[] senderDsaPub = Convert.FromBase64String(senderCard.MlDsaPub);
                var dsaVerifier = new MLDsaSigner(MLDsaParameters.ml_dsa_65, deterministic: false);
                dsaVerifier.Init(false, MLDsaPublicKeyParameters.FromEncoding(MLDsaParameters.ml_dsa_65, senderDsaPub));
                dsaVerifier.BlockUpdate(sigInput, 0, sigInput.Length);
                if (!dsaVerifier.VerifySignature(dsaSig))
                    throw new CryptographicException("ML-DSA-65 post-quantum signature verification failed.");
                pqSigVerified = true;
            }

            return new OpenedEnvelope
            {
                Verified = true,
                PostQuantumSignatureVerified = pqSigVerified,
                SentAt = inner.sentAt,
                Message = inner.message,
                Attachment = inner.attachment,
                Sender = senderCard,
                TranscriptHashHex = Convert.ToHexString(transcriptHash).ToLowerInvariant(),
                TotalPacketBytes = packetBytes.Length,
                PaddedPlaintextBytes = paddedInner.Length,
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(recipientXPriv);
            CryptographicOperations.ZeroMemory(recipientPqPriv);
            if (ssEcdh != null) CryptographicOperations.ZeroMemory(ssEcdh);
            if (ssPq != null) CryptographicOperations.ZeroMemory(ssPq);
            if (sessionKey != null) CryptographicOperations.ZeroMemory(sessionKey);
        }
    }

    public static bool IsPassphrasePacket(byte[] buf) =>
        buf.Length >= PassHeaderLen + GcmTagLen && buf.AsSpan(0, 6).SequenceEqual(EnvelopeMagicPassV2);

    public static SealedResult SealWithPassphrase(string passphrase, string message, VeilAttachment? attachment = null)
    {
        if (string.IsNullOrEmpty(passphrase))
            throw new ArgumentException("Passphrase cannot be empty.");

        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte flags = (byte)(attachment != null ? 0x02 : 0x00);

        byte[] header = new byte[PassHeaderLen];
        Buffer.BlockCopy(EnvelopeMagicPassV2, 0, header, 0, 6);
        header[6] = flags;
        Buffer.BlockCopy(salt, 0, header, 7, 16);
        Buffer.BlockCopy(nonce, 0, header, 23, 12);

        byte[] key = DeriveArgon2idKey(passphrase, salt);
        try
        {
            string sentAt = DateTime.UtcNow.ToString("O");
            var inner = new InnerPayloadDto
            {
                v = ProtocolVersion,
                sentAt = sentAt,
                senderCard = "",
                message = message ?? "",
                attachment = attachment,
            };

            byte[] payloadBytes = JsonSerializer.SerializeToUtf8Bytes(inner);
            byte[] paddedInner = PadPlaintext(payloadBytes);

            byte[] ct = new byte[paddedInner.Length];
            byte[] tag = new byte[GcmTagLen];
            using (var gcm = new AesGcm(key, GcmTagLen))
            {
                gcm.Encrypt(nonce, paddedInner, ct, tag, header);
            }
            CryptographicOperations.ZeroMemory(paddedInner);

            byte[] packet = new byte[PassHeaderLen + ct.Length + GcmTagLen];
            Buffer.BlockCopy(header, 0, packet, 0, PassHeaderLen);
            Buffer.BlockCopy(ct, 0, packet, PassHeaderLen, ct.Length);
            Buffer.BlockCopy(tag, 0, packet, PassHeaderLen + ct.Length, GcmTagLen);

            return new SealedResult
            {
                PacketBytes = packet,
                TranscriptHashHex = Convert.ToHexString(SHA256.HashData(header)).ToLowerInvariant(),
                PaddedInnerBytes = ct.Length,
                SentAt = sentAt,
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    public static OpenedEnvelope OpenWithPassphrase(string passphrase, byte[] packetBytes)
    {
        if (!IsPassphrasePacket(packetBytes))
            throw new InvalidDataException("Not a passphrase-encrypted Veil file.");

        byte[] header = packetBytes[..PassHeaderLen];
        byte[] salt = packetBytes[7..23];
        byte[] nonce = packetBytes[23..35];
        byte[] ct = packetBytes[PassHeaderLen..^GcmTagLen];
        byte[] tag = packetBytes[^GcmTagLen..];

        byte[] key = DeriveArgon2idKey(passphrase, salt);
        try
        {
            byte[] paddedInner = new byte[ct.Length];
            try
            {
                using var gcm = new AesGcm(key, GcmTagLen);
                gcm.Decrypt(nonce, ct, tag, paddedInner, header);
            }
            catch
            {
                throw new CryptographicException("Wrong passphrase or tampered .veil file.");
            }

            byte[] payloadBytes = UnpadPlaintext(paddedInner);
            CryptographicOperations.ZeroMemory(paddedInner);

            var inner = JsonSerializer.Deserialize<InnerPayloadDto>(payloadBytes)
                ?? throw new InvalidDataException("Corrupt inner payload.");

            return new OpenedEnvelope
            {
                Verified = true,
                PostQuantumSignatureVerified = false,
                IsPassphraseMode = true,
                SentAt = inner.sentAt,
                Message = inner.message,
                Attachment = inner.attachment,
                Sender = new VeilContactCard { DisplayName = "Passphrase-Encrypted (No Key Pair)" },
                TranscriptHashHex = Convert.ToHexString(SHA256.HashData(header)).ToLowerInvariant(),
                TotalPacketBytes = packetBytes.Length,
                PaddedPlaintextBytes = ct.Length,
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    public static PacketInspection InspectPacket(byte[] buf)
    {
        if (IsPassphrasePacket(buf))
        {
            byte[] pHeader = buf[..PassHeaderLen];
            int pCtLen = buf.Length - PassHeaderLen - GcmTagLen;
            return new PacketInspection
            {
                Protocol = "VEIL-2 Passphrase Mode (Argon2id + AES-256-GCM)",
                TotalBytes = buf.Length,
                TranscriptHashHex = Convert.ToHexString(SHA256.HashData(pHeader)).ToLowerInvariant(),
                VisibleOnWire = new Dictionary<string, string>
                {
                    ["Mode"] = "Symmetric Passphrase (Argon2id 64 MiB + AES-256-GCM)",
                    ["Timestamp & Filename"] = "HIDDEN (Encrypted inside inner envelope)",
                    ["Exact Length"] = $"OBSCURED (Power-of-2 bucket: {pCtLen:N0} bytes)",
                },
                Segments = new List<PacketSegment>
                {
                    new() { Offset = 0, Length = 6, Name = "Magic & Version", HexPreview = Convert.ToHexString(buf[..6]).ToLowerInvariant(), Role = "Protocol identifier (VEILP2)" },
                    new() { Offset = 6, Length = 1, Name = "Flags", HexPreview = buf[6].ToString("x2"), Role = "Envelope capability flags" },
                    new() { Offset = 7, Length = 16, Name = "Argon2id Salt", HexPreview = Convert.ToHexString(buf[7..23]).ToLowerInvariant(), Role = "128-bit CSPRNG KDF salt" },
                    new() { Offset = 23, Length = 12, Name = "AES-GCM Nonce", HexPreview = Convert.ToHexString(buf[23..35]).ToLowerInvariant(), Role = "96-bit CSPRNG nonce" },
                    new() { Offset = 35, Length = pCtLen, Name = "Encrypted Padded Payload", HexPreview = Convert.ToHexString(buf[35..Math.Min(51, buf.Length - 16)]).ToLowerInvariant() + "…", Role = "Encrypted message, file & random padding" },
                    new() { Offset = buf.Length - 16, Length = 16, Name = "GCM Auth Tag", HexPreview = Convert.ToHexString(buf[^16..]).ToLowerInvariant(), Role = "128-bit integrity tag bound to header" },
                }
            };
        }

        if (buf.Length < OuterHeaderLen + GcmTagLen)
            throw new InvalidDataException("Packet too small to be a valid Veil envelope.");

        string proto;
        if (buf.AsSpan(0, 6).SequenceEqual(EnvelopeMagicV2)) proto = "VEIL-2 (Full Post-Quantum Hybrid)";
        else if (buf.AsSpan(0, 6).SequenceEqual(EnvelopeMagicV1)) proto = "VEIL-1 (Legacy PQ-KEM)";
        else throw new InvalidDataException("Not a Veil envelope (magic mismatch).");

        byte[] outerHeader = buf[..OuterHeaderLen];
        byte[] transcriptHash = SHA256.HashData(outerHeader);
        int ctLen = buf.Length - OuterHeaderLen - GcmTagLen;

        return new PacketInspection
        {
            Protocol = proto,
            TotalBytes = buf.Length,
            TranscriptHashHex = Convert.ToHexString(transcriptHash).ToLowerInvariant(),
            VisibleOnWire = new Dictionary<string, string>
            {
                ["Sender Identity"] = "HIDDEN (Sealed inside AES-256-GCM)",
                ["Recipient Identity"] = "HIDDEN (Zero KeyID in outer header)",
                ["Signatures"] = proto.StartsWith("VEIL-2") ? "HIDDEN (ML-DSA-65 + Ed25519 inside)" : "HIDDEN (Ed25519 inside)",
                ["Timestamp & Filename"] = "HIDDEN (Encrypted inside inner envelope)",
                ["Exact Length"] = $"OBSCURED (Power-of-2 bucket: {ctLen:N0} bytes)",
            },
            Segments = new List<PacketSegment>
            {
                new() { Offset = 0, Length = 6, Name = "Magic & Version", HexPreview = Convert.ToHexString(buf[..6]).ToLowerInvariant(), Role = $"Protocol identifier ({proto})" },
                new() { Offset = 6, Length = 1, Name = "Flags", HexPreview = buf[6].ToString("x2"), Role = "Envelope capability flags" },
                new() { Offset = 7, Length = 32, Name = "Ephemeral X25519 PK", HexPreview = Convert.ToHexString(buf[7..23]).ToLowerInvariant() + "…", Role = "Fresh per-message classical ECDH key" },
                new() { Offset = 39, Length = 1088, Name = "ML-KEM-768 Ciphertext", HexPreview = Convert.ToHexString(buf[39..55]).ToLowerInvariant() + "…", Role = "Post-quantum lattice encapsulation (FIPS 203)" },
                new() { Offset = 1127, Length = 12, Name = "AES-GCM Nonce", HexPreview = Convert.ToHexString(buf[1127..1139]).ToLowerInvariant(), Role = "96-bit CSPRNG nonce" },
                new() { Offset = 1139, Length = ctLen, Name = "Encrypted Padded Payload", HexPreview = Convert.ToHexString(buf[1139..Math.Min(1155, buf.Length - 16)]).ToLowerInvariant() + "…", Role = "Sealed sender, ML-DSA-65 + Ed25519 signatures, message, file & padding" },
                new() { Offset = buf.Length - 16, Length = 16, Name = "GCM Auth Tag", HexPreview = Convert.ToHexString(buf[^16..]).ToLowerInvariant(), Role = "128-bit integrity tag bound to entire outer header" },
            }
        };
    }

    public static byte[] EncryptVault<T>(T vaultObj, string passphrase)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] key = DeriveArgon2idKey(passphrase, salt);
        try
        {
            byte[] header = new byte[8 + 16 + 12];
            Buffer.BlockCopy(VaultMagicV2, 0, header, 0, 8);
            Buffer.BlockCopy(salt, 0, header, 8, 16);
            Buffer.BlockCopy(nonce, 0, header, 24, 12);

            byte[] plain = JsonSerializer.SerializeToUtf8Bytes(vaultObj);
            byte[] ct = new byte[plain.Length];
            byte[] tag = new byte[GcmTagLen];
            using (var gcm = new AesGcm(key, GcmTagLen))
            {
                gcm.Encrypt(nonce, plain, ct, tag, header);
            }
            CryptographicOperations.ZeroMemory(plain);

            byte[] output = new byte[header.Length + ct.Length + GcmTagLen];
            Buffer.BlockCopy(header, 0, output, 0, header.Length);
            Buffer.BlockCopy(ct, 0, output, header.Length, ct.Length);
            Buffer.BlockCopy(tag, 0, output, header.Length + ct.Length, GcmTagLen);
            return output;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    public static T DecryptVault<T>(byte[] vaultBytes, string passphrase)
    {
        if (vaultBytes.Length < 36 + GcmTagLen)
            throw new InvalidDataException("Invalid Veil vault file.");

        bool isV2 = vaultBytes.AsSpan(0, 8).SequenceEqual(VaultMagicV2);
        bool isV1 = !isV2 && vaultBytes.AsSpan(0, 8).SequenceEqual(VaultMagicV1);
        if (!isV2 && !isV1)
            throw new InvalidDataException("Invalid Veil vault file.");

        byte[] header = vaultBytes[..36];
        byte[] salt = vaultBytes[8..24];
        byte[] nonce = vaultBytes[24..36];
        byte[] ct = vaultBytes[36..^GcmTagLen];
        byte[] tag = vaultBytes[^GcmTagLen..];

        byte[] key = isV2
            ? DeriveArgon2idKey(passphrase, salt)
            : SCrypt.Generate(Encoding.UTF8.GetBytes(passphrase), salt, 16384, 8, 1, 32);

        try
        {
            byte[] plain = new byte[ct.Length];
            using (var gcm = new AesGcm(key, GcmTagLen))
            {
                gcm.Decrypt(nonce, ct, tag, plain, header);
            }
            try
            {
                return JsonSerializer.Deserialize<T>(plain) ?? throw new InvalidDataException("Corrupt vault.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plain);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    public static byte[] ExportEncryptedPrivateKey(VeilIdentity identity, string backupPassphrase)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] key = DeriveArgon2idKey(backupPassphrase, salt);
        try
        {
            byte[] header = new byte[6 + 16 + 12];
            Buffer.BlockCopy(PrivKeyMagicV2, 0, header, 0, 6);
            Buffer.BlockCopy(salt, 0, header, 6, 16);
            Buffer.BlockCopy(nonce, 0, header, 22, 12);

            byte[] plain = JsonSerializer.SerializeToUtf8Bytes(identity);
            byte[] ct = new byte[plain.Length];
            byte[] tag = new byte[GcmTagLen];
            using (var gcm = new AesGcm(key, GcmTagLen))
            {
                gcm.Encrypt(nonce, plain, ct, tag, header);
            }
            CryptographicOperations.ZeroMemory(plain);

            byte[] output = new byte[header.Length + ct.Length + GcmTagLen];
            Buffer.BlockCopy(header, 0, output, 0, header.Length);
            Buffer.BlockCopy(ct, 0, output, header.Length, ct.Length);
            Buffer.BlockCopy(tag, 0, output, header.Length + ct.Length, GcmTagLen);
            return output;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    public static VeilIdentity ImportEncryptedPrivateKey(byte[] backupBytes, string backupPassphrase)
    {
        if (backupBytes.Length < 34 + GcmTagLen)
            throw new InvalidDataException("Invalid Veil private key backup (.veilkey).");

        bool isV2 = backupBytes.AsSpan(0, 6).SequenceEqual(PrivKeyMagicV2);
        bool isV1 = !isV2 && backupBytes.AsSpan(0, 6).SequenceEqual(PrivKeyMagicV1);
        if (!isV2 && !isV1)
            throw new InvalidDataException("Invalid Veil private key backup (.veilkey).");

        byte[] header = backupBytes[..34];
        byte[] salt = backupBytes[6..22];
        byte[] nonce = backupBytes[22..34];
        byte[] ct = backupBytes[34..^GcmTagLen];
        byte[] tag = backupBytes[^GcmTagLen..];

        byte[] key = isV2
            ? DeriveArgon2idKey(backupPassphrase, salt)
            : SCrypt.Generate(Encoding.UTF8.GetBytes(backupPassphrase), salt, 16384, 8, 1, 32);

        try
        {
            byte[] plain = new byte[ct.Length];
            try
            {
                using var gcm = new AesGcm(key, GcmTagLen);
                gcm.Decrypt(nonce, ct, tag, plain, header);
            }
            catch
            {
                throw new CryptographicException("Wrong backup passphrase or corrupted .veilkey file.");
            }
            try
            {
                return JsonSerializer.Deserialize<VeilIdentity>(plain)
                    ?? throw new InvalidDataException("Corrupt private key payload.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plain);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }
}

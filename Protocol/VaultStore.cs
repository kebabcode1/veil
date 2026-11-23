using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace VeilDesktop.Protocol;

public sealed class ContactEntry
{
    public string DisplayName { get; set; } = "";
    public string FingerprintHex { get; set; } = "";
    public string ShortId { get; set; } = "";
    public string SafetyPhrase { get; set; } = "";
    public string CardBase64 { get; set; } = "";
    public string Uri { get; set; } = "";
    public bool Verified { get; set; }
    public bool HasPrivateKey { get; set; }
    public bool IsActiveKey { get; set; }
    public bool IsFullPostQuantum { get; set; } = true;
    public string AddedAt { get; set; } = "";

    public string Algorithm => IsFullPostQuantum
        ? "ML-KEM-768 + ML-DSA-65 + X25519 + Ed25519"
        : "ML-KEM-768 + X25519 + Ed25519 (v1)";
    public string KeyTypeLabel => HasPrivateKey
        ? (IsActiveKey ? "ACTIVE Private + Public" : "Private + Public (Inactive)")
        : "Public Key Only (Contact)";
    public string TrustLabel => HasPrivateKey ? "Ultimate (Own Key)" : (Verified ? "Verified" : "Unverified");
    public string AddedDate => DateTime.TryParse(AddedAt, out var dt) ? dt.ToLocalTime().ToString("yyyy-MM-dd HH:mm") : AddedAt;
}

public sealed class VaultData
{

    public VeilIdentity? Identity { get; set; }
    public string? ActiveIdentityFingerprint { get; set; }
    public List<VeilIdentity> OwnIdentities { get; set; } = new();
    public List<ContactEntry> Contacts { get; set; } = new();
}

public sealed class VaultManager
{
    public string DataDir { get; }
    public string VaultFile { get; }

    public VaultData? Vault { get; private set; }
    private string? _passphrase;

    public VaultManager()
    {
        DataDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "VEIL-1");
        VaultFile = Path.Combine(DataDir, "vault.veilvault");
        Directory.CreateDirectory(DataDir);
    }

    public bool VaultExists => File.Exists(VaultFile);
    public bool IsUnlocked => Vault != null;

    public void Save()
    {
        if (Vault == null || _passphrase == null) return;
        File.WriteAllBytes(VaultFile, VeilProtocol.EncryptVault(Vault, _passphrase));
    }

    public void CreateVault(string displayName, string passphrase)
    {
        var id = VeilProtocol.GenerateIdentity(displayName);
        Vault = new VaultData
        {
            ActiveIdentityFingerprint = id.FingerprintHex,
            OwnIdentities = new List<VeilIdentity> { id },
            Contacts = new List<ContactEntry>(),
        };
        _passphrase = passphrase;
        Save();
    }

    public void Unlock(string passphrase)
    {
        if (!VaultExists) throw new FileNotFoundException("Vault file does not exist.");
        var loaded = VeilProtocol.DecryptVault<VaultData>(File.ReadAllBytes(VaultFile), passphrase);
        if (loaded.OwnIdentities.Count == 0 && loaded.Identity != null && !string.IsNullOrEmpty(loaded.Identity.FingerprintHex))
        {
            loaded.OwnIdentities.Add(loaded.Identity);
            loaded.Identity = null;
        }
        loaded.Contacts.RemoveAll(c => c.DisplayName.Contains("Local Demo Peer", StringComparison.OrdinalIgnoreCase));
        if (string.IsNullOrEmpty(loaded.ActiveIdentityFingerprint) ||
            !loaded.OwnIdentities.Any(x => x.FingerprintHex == loaded.ActiveIdentityFingerprint))
        {
            loaded.ActiveIdentityFingerprint = loaded.OwnIdentities.FirstOrDefault()?.FingerprintHex;
        }
        Vault = loaded;
        _passphrase = passphrase;
        Save();
    }

    public VeilIdentity? ActiveIdentity =>
        Vault == null
            ? null
            : Vault.OwnIdentities.FirstOrDefault(x => x.FingerprintHex == Vault.ActiveIdentityFingerprint)
              ?? Vault.OwnIdentities.FirstOrDefault();

    public void SetActiveIdentity(string fingerprintHex)
    {
        if (Vault == null) return;
        if (Vault.OwnIdentities.Any(x => x.FingerprintHex == fingerprintHex))
        {
            Vault.ActiveIdentityFingerprint = fingerprintHex;
            Save();
        }
    }

    public void Lock()
    {
        Vault = null;
        _passphrase = null;
        GC.Collect();
        GC.WaitForPendingFinalizers();
    }

    public VeilIdentity CreateNewKeyPair(string displayName)
    {
        if (Vault == null) throw new InvalidOperationException("Vault is locked.");
        var id = VeilProtocol.GenerateIdentity(displayName);
        Vault.OwnIdentities.Add(id);
        Save();
        return id;
    }

    public VeilIdentity ImportPrivateKey(byte[] backupBytes, string backupPassphrase)
    {
        if (Vault == null) throw new InvalidOperationException("Vault is locked.");
        var id = VeilProtocol.ImportEncryptedPrivateKey(backupBytes, backupPassphrase);
        if (Vault.OwnIdentities.Any(x => x.FingerprintHex == id.FingerprintHex))
            throw new InvalidOperationException($"Private key \"{id.DisplayName}\" ({id.ShortId}) is already in your keyring.");

        Vault.Contacts.RemoveAll(c => c.FingerprintHex == id.FingerprintHex);
        Vault.OwnIdentities.Add(id);
        Save();
        return id;
    }

    public VeilIdentity? FindOwnIdentity(string fingerprintHex) =>
        Vault?.OwnIdentities.FirstOrDefault(x => x.FingerprintHex == fingerprintHex);

    public List<ContactEntry> GetAllKeyRows()
    {
        var rows = new List<ContactEntry>();
        if (Vault == null) return rows;
        var activeFp = ActiveIdentity?.FingerprintHex;

        foreach (var id in Vault.OwnIdentities)
        {
            var card = VeilProtocol.ExportContactCard(id);
            rows.Add(new ContactEntry
            {
                DisplayName = id.DisplayName,
                FingerprintHex = id.FingerprintHex,
                ShortId = id.ShortId,
                SafetyPhrase = id.SafetyPhrase,
                CardBase64 = card.CardBase64,
                Uri = card.Uri,
                Verified = true,
                HasPrivateKey = true,
                IsActiveKey = id.FingerprintHex == activeFp,
                IsFullPostQuantum = id.IsFullPostQuantum,
                AddedAt = id.CreatedAt,
            });
        }

        rows.AddRange(Vault.Contacts);
        return rows;
    }

    public ContactEntry ImportPublicKey(byte[] bytes) => ImportParsedPublicKey(VeilProtocol.ParseContactCard(bytes));
    public ContactEntry ImportPublicKey(string text) => ImportParsedPublicKey(VeilProtocol.ParseContactCard(text));

    private ContactEntry ImportParsedPublicKey(VeilContactCard parsed)
    {
        if (Vault == null) throw new InvalidOperationException("Vault is locked.");
        if (Vault.OwnIdentities.Any(x => x.FingerprintHex == parsed.FingerprintHex))
            throw new InvalidOperationException("That public key belongs to one of your own private key pairs.");

        var existing = Vault.Contacts.FirstOrDefault(c => c.FingerprintHex == parsed.FingerprintHex);
        if (existing != null)
        {
            existing.DisplayName = parsed.DisplayName;
            existing.CardBase64 = parsed.CardBase64;
            existing.Uri = parsed.Uri;
            Save();
            return existing;
        }

        var entry = new ContactEntry
        {
            DisplayName = parsed.DisplayName,
            FingerprintHex = parsed.FingerprintHex,
            ShortId = parsed.ShortId,
            SafetyPhrase = parsed.SafetyPhrase,
            CardBase64 = parsed.CardBase64,
            Uri = parsed.Uri,
            Verified = false,
            HasPrivateKey = false,
            IsFullPostQuantum = parsed.IsFullPostQuantum,
            AddedAt = DateTime.UtcNow.ToString("O"),
        };
        Vault.Contacts.Add(entry);
        Save();
        return entry;
    }

    public void DeleteKey(string fingerprintHex)
    {
        if (Vault == null) return;
        Vault.Contacts.RemoveAll(c => c.FingerprintHex == fingerprintHex);
        if (Vault.OwnIdentities.Any(x => x.FingerprintHex == fingerprintHex))
        {
            if (Vault.OwnIdentities.Count <= 1)
                throw new InvalidOperationException("You must keep at least one private key pair in your vault.");
            Vault.OwnIdentities.RemoveAll(x => x.FingerprintHex == fingerprintHex);
            if (Vault.ActiveIdentityFingerprint == fingerprintHex)
                Vault.ActiveIdentityFingerprint = Vault.OwnIdentities.FirstOrDefault()?.FingerprintHex;
        }
        Save();
    }

    public (OpenedEnvelope Envelope, VeilIdentity ActiveKey) DecryptWithActiveKey(byte[] packetBytes)
    {
        var active = ActiveIdentity
            ?? throw new InvalidOperationException("Vault is locked or has no active key set.");

        try
        {
            var opened = VeilProtocol.OpenEnvelope(active, packetBytes);
            return (opened, active);
        }
        catch (CryptographicException)
        {
            throw new CryptographicException(
                $"Decryption failed: this .veil file was NOT encrypted for the active key set \"{active.DisplayName}\" [{active.ShortId}] (or the file was tampered with).\n\nSwitch to the intended Key Set in the top toolbar to decrypt it.");
        }
    }
}

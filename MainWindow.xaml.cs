using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using Microsoft.Win32;
using VeilDesktop.Dialogs;
using VeilDesktop.Protocol;

namespace VeilDesktop;

public partial class MainWindow : Window
{
    private readonly VaultManager _manager = new();
    private VeilAttachment? _pendingAttachment;
    private OpenedEnvelope? _lastDecrypted;
    private byte[]? _lastDecryptedBytes;
    private string _lastDecryptedFileName = "";
    private bool _suppressSwitcherEvent;
    private readonly DispatcherTimer _idleTimer;
    private DateTime _lastActivity = DateTime.UtcNow;

    public MainWindow()
    {
        InitializeComponent();
        PreviewMouseDown += (_, _) => _lastActivity = DateTime.UtcNow;
        PreviewKeyDown += (_, _) => _lastActivity = DateTime.UtcNow;

        _idleTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(15) };
        _idleTimer.Tick += (_, _) =>
        {
            if (_manager.IsUnlocked && (DateTime.UtcNow - _lastActivity) >= TimeSpan.FromMinutes(5))
            {
                _manager.Lock();
                ClearDecryptedPanel();
                RefreshUI();
                StatusText.Text = "Vault auto-locked after 5 minutes of inactivity";
                EnsureUnlocked();
            }
        };
        _idleTimer.Start();

        Loaded += (_, _) =>
        {
            if (EnsureUnlocked())
                ProcessStartupArgs();
        };
    }

    private void ProcessStartupArgs()
    {
        var args = App.StartupArgs;
        if (args == null || args.Length == 0) return;

        if (args.Length >= 2 && args[0].Equals("--encrypt", StringComparison.OrdinalIgnoreCase) && File.Exists(args[1]))
        {
            AttachFilePath(args[1]);
            MainTabs.SelectedIndex = 1;
            ComposeBox.Focus();
            return;
        }

        string target = args[0];
        if (!File.Exists(target)) return;

        if (target.EndsWith(".veil", StringComparison.OrdinalIgnoreCase))
            DecryptVeilFile(target);
        else if (target.EndsWith(".veilpub", StringComparison.OrdinalIgnoreCase) || target.EndsWith(".veilcard", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                var entry = _manager.ImportPublicKey(File.ReadAllBytes(target));
                RefreshUI();
                MessageBox.Show(this, $"Verified & added contact public key:\n{entry.DisplayName} ({entry.SafetyPhrase})",
                    "Contact Added", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Import Failed", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        else if (target.EndsWith(".veilkey", StringComparison.OrdinalIgnoreCase))
            ImportPrivateKeyFile(target);
        else
        {
            AttachFilePath(target);
            MainTabs.SelectedIndex = 1;
            ComposeBox.Focus();
        }
    }

    private void RegisterWindows_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            WindowsIntegration.Register();
            StatusText.Text = "Registered .veil, .veilpub, .veilkey file associations & Explorer right-click menu";
            MessageBox.Show(this,
                "Windows integration enabled for your user account:\n\n" +
                "• Double-click .veil files to open & decrypt in Veil\n" +
                "• Double-click .veilpub / .veilkey files to import\n" +
                "• Right-click any file in Explorer → \"Encrypt with Veil\"",
                "Windows Integration Registered", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Registration Failed", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void UnregisterWindows_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            WindowsIntegration.Unregister();
            StatusText.Text = "Removed Windows file associations & Explorer right-click menu";
            MessageBox.Show(this, "Removed Veil file associations and Explorer context menu.",
                "Windows Integration Removed", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Unregister Failed", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private bool EnsureUnlocked()
    {
        if (_manager.IsUnlocked) return true;

        var dlg = new VaultDialog(createMode: !_manager.VaultExists) { Owner = this };
        dlg.ValidateAction = (name, pass) =>
        {
            try
            {
                if (dlg.IsCreateMode) _manager.CreateVault(name, pass);
                else _manager.Unlock(pass);
                return null;
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        };

        if (dlg.ShowDialog() == true)
        {
            RefreshUI();
            return true;
        }

        if (!_manager.IsUnlocked) Close();
        return false;
    }

    private void RefreshUI()
    {
        if (_manager.Vault == null)
        {
            KeysGrid.ItemsSource = null;
            ActiveKeyCombo.ItemsSource = null;
            ActiveSignerBox.Text = "";
            RecipientCombo.ItemsSource = null;
            StatusText.Text = "Vault locked";
            return;
        }

        var active = _manager.ActiveIdentity;
        int ownCount = _manager.Vault.OwnIdentities.Count;
        int contactCount = _manager.Vault.Contacts.Count;
        StatusText.Text = active != null
            ? $"Active Key Set: {active.DisplayName} [{active.ShortId}] ({active.SafetyPhrase})  |  My Key Sets: {ownCount}  |  Contacts: {contactCount}"
            : $"Vault unlocked  |  My Key Sets: {ownCount}  |  Contacts: {contactCount}";

        _suppressSwitcherEvent = true;
        ActiveKeyCombo.ItemsSource = _manager.Vault.OwnIdentities.ToList();
        ActiveKeyCombo.SelectedItem = _manager.Vault.OwnIdentities.FirstOrDefault(x => x.FingerprintHex == active?.FingerprintHex);
        _suppressSwitcherEvent = false;

        ActiveSignerBox.Text = active != null ? active.SwitcherLabel : "(none)";

        ApplyKeyFilter();

        var allRecipients = _manager.GetAllKeyRows();
        var prevRecip = (RecipientCombo.SelectedItem as ContactEntry)?.FingerprintHex;
        RecipientCombo.ItemsSource = allRecipients;
        RecipientCombo.SelectedItem = allRecipients.FirstOrDefault(x => x.FingerprintHex == prevRecip)
            ?? allRecipients.FirstOrDefault(x => !x.IsActiveKey)
            ?? allRecipients.FirstOrDefault();
    }

    private void ClearDecryptedPanel()
    {
        _lastDecrypted = null;
        _lastDecryptedBytes = null;
        _lastDecryptedFileName = "";
        DecStatusHeader.Text = "No .veil file opened yet";
        DecSenderLine.Text = "";
        DecMetaLine.Text = "";
        DecMessageBox.Text = "";
        BtnSaveDecAttachment.Visibility = Visibility.Collapsed;
        BtnAddSenderContact.Visibility = Visibility.Collapsed;
        BtnInspectDecPacket.Visibility = Visibility.Collapsed;
    }

    private void ActiveKeyCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_suppressSwitcherEvent || _manager.Vault == null) return;
        if (ActiveKeyCombo.SelectedItem is VeilIdentity chosen)
        {
            _manager.SetActiveIdentity(chosen.FingerprintHex);
            ClearDecryptedPanel();
            RefreshUI();
        }
    }

    private void CtxSwitchToKey_Click(object sender, RoutedEventArgs e)
    {
        if (_manager.Vault == null) return;
        if (KeysGrid.SelectedItem is ContactEntry entry && entry.HasPrivateKey)
        {
            _manager.SetActiveIdentity(entry.FingerprintHex);
            ClearDecryptedPanel();
            RefreshUI();
        }
        else
        {
            MessageBox.Show(this, "You can only switch to one of your own Private + Public Key Sets.",
                "Switch Key Set", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    private void ApplyKeyFilter()
    {
        if (_manager.Vault == null) return;
        var rows = _manager.GetAllKeyRows();
        string q = (SearchBox?.Text ?? "").Trim();
        int filterIdx = FilterCombo?.SelectedIndex ?? 0;

        IEnumerable<ContactEntry> filtered = rows;
        if (filterIdx == 1) filtered = filtered.Where(r => r.HasPrivateKey);
        else if (filterIdx == 2) filtered = filtered.Where(r => !r.HasPrivateKey);
        else if (filterIdx == 3) filtered = filtered.Where(r => !r.HasPrivateKey && r.Verified);

        if (!string.IsNullOrEmpty(q))
        {
            filtered = filtered.Where(r =>
                r.DisplayName.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                r.SafetyPhrase.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                r.ShortId.Contains(q, StringComparison.OrdinalIgnoreCase));
        }

        KeysGrid.ItemsSource = filtered.ToList();
    }

    private void Filter_Changed(object sender, EventArgs e) => ApplyKeyFilter();

    private void KeysGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (KeysGrid.SelectedItem is ContactEntry entry)
        {
            DetailHeader.Text = $"{entry.DisplayName}  —  {entry.KeyTypeLabel}  |  Safety Phrase: {entry.SafetyPhrase}";
            DetailFingerprint.Text = $"SHA-256 Fingerprint: {entry.FingerprintHex}   |   Suite: {entry.Algorithm}";
            BtnBackupPriv.IsEnabled = entry.HasPrivateKey;
            BtnCopyPub.IsEnabled = true;
            BtnExportPub.IsEnabled = true;
            BtnEncryptFor.IsEnabled = true;
        }
        else
        {
            DetailHeader.Text = "Select a key to view details";
            DetailFingerprint.Text = "";
            BtnBackupPriv.IsEnabled = false;
            BtnCopyPub.IsEnabled = false;
            BtnExportPub.IsEnabled = false;
            BtnEncryptFor.IsEnabled = false;
        }
    }

    private void KeysGrid_DoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (KeysGrid.SelectedItem is ContactEntry entry)
            SelectRecipientAndGoToEncrypt(entry);
    }

    private void SelectRecipientAndGoToEncrypt(ContactEntry entry)
    {
        MainTabs.SelectedIndex = 1;
        var list = RecipientCombo.ItemsSource as IEnumerable<ContactEntry>;
        RecipientCombo.SelectedItem = list?.FirstOrDefault(x => x.FingerprintHex == entry.FingerprintHex);
        ComposeBox.Focus();
    }

    private void NewKeyPair_Click(object sender, RoutedEventArgs e)
    {
        if (_manager.Vault == null) return;
        var dlg = new PromptDialog(
            "New Veil Key Set",
            "Enter a name for your new Private + Public Key Set (e.g. Work, Personal, Alice, Bob):",
            isPassword: false,
            note: "Generates independent ML-KEM-768 + ML-DSA-65 + X25519 + Ed25519 keys. Messages encrypted to one key set cannot be decrypted by another.",
            okText: "Generate & Switch") { Owner = this };

        if (dlg.ShowDialog() != true) return;
        var id = _manager.CreateNewKeyPair(dlg.Value);
        _manager.SetActiveIdentity(id.FingerprintHex);
        ClearDecryptedPanel();
        RefreshUI();
        MessageBox.Show(this,
            $"Generated & switched to new Key Set:\n\nName: {id.DisplayName}\nKey ID: {id.ShortId}\nSafety Phrase: {id.SafetyPhrase}",
            "Key Set Created", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void ImportPublicKey_Click(object sender, RoutedEventArgs e)
    {
        if (_manager.Vault == null) return;
        var dlg = new ImportCardDialog { Owner = this };
        if (dlg.ShowDialog() != true) return;
        try
        {
            var entry = dlg.SelectedFileBytes != null
                ? _manager.ImportPublicKey(dlg.SelectedFileBytes)
                : _manager.ImportPublicKey(dlg.EnteredUri!);
            RefreshUI();
            MessageBox.Show(this,
                $"Verified & added contact public key:\n\nName: {entry.DisplayName}\nSafety Phrase: {entry.SafetyPhrase}\nKey ID: {entry.ShortId}",
                "Contact Added", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Import Public Key Failed", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private ContactEntry? GetSelectedOrDefaultOwnEntry()
    {
        if (KeysGrid.SelectedItem is ContactEntry sel) return sel;
        var activeFp = _manager.ActiveIdentity?.FingerprintHex;
        return _manager.GetAllKeyRows().FirstOrDefault(x => x.FingerprintHex == activeFp)
            ?? _manager.GetAllKeyRows().FirstOrDefault(x => x.HasPrivateKey);
    }

    private void ExportSelectedPublicKey_Click(object sender, RoutedEventArgs e)
    {
        var entry = GetSelectedOrDefaultOwnEntry();
        if (entry == null) return;

        string safe = new string(entry.DisplayName.Select(ch => char.IsLetterOrDigit(ch) ? ch : '_').ToArray());
        var dlg = new SaveFileDialog
        {
            Title = "Export Public Key (.veilpub)",
            FileName = $"{safe}.veilpub",
            Filter = "Veil Public Key (*.veilpub)|*.veilpub|All Files (*.*)|*.*"
        };
        if (dlg.ShowDialog(this) == true)
        {
            File.WriteAllBytes(dlg.FileName, Convert.FromBase64String(entry.CardBase64));
            StatusText.Text = $"Exported public key: {dlg.FileName}";
        }
    }

    private void CopySelectedPublicKey_Click(object sender, RoutedEventArgs e)
    {
        var entry = GetSelectedOrDefaultOwnEntry();
        if (entry == null) return;
        Clipboard.SetText(entry.Uri);
        StatusText.Text = $"Copied public key (veilpub1:…) for {entry.DisplayName} to clipboard";
    }

    private void BackupSelectedPrivateKey_Click(object sender, RoutedEventArgs e)
    {
        if (_manager.Vault == null) return;
        var entry = KeysGrid.SelectedItem as ContactEntry;
        if (entry == null || !entry.HasPrivateKey)
        {
            entry = _manager.GetAllKeyRows().FirstOrDefault(x => x.HasPrivateKey);
        }
        if (entry == null) return;

        var ownId = _manager.FindOwnIdentity(entry.FingerprintHex);
        if (ownId == null)
        {
            MessageBox.Show(this, "Only your own keys have a private key to back up.", "Backup Private Key",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var passDlg = new PromptDialog(
            "Backup Private Key (.veilkey)",
            $"Set a strong passphrase to encrypt the private key backup for \"{ownId.DisplayName}\":",
            isPassword: true,
            note: "WARNING: Keep this .veilkey file strictly private. Never share it with anyone — only share your .veilpub Public Key.",
            okText: "Continue") { Owner = this };

        if (passDlg.ShowDialog() != true) return;
        if (passDlg.Value.Length < 4)
        {
            MessageBox.Show(this, "Backup passphrase must be at least 4 characters.", "Backup Private Key",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        string safe = new string(ownId.DisplayName.Select(ch => char.IsLetterOrDigit(ch) ? ch : '_').ToArray());
        var saveDlg = new SaveFileDialog
        {
            Title = "Save Encrypted Private Key Backup",
            FileName = $"{safe}-PRIVATE.veilkey",
            Filter = "Veil Encrypted Private Key (*.veilkey)|*.veilkey"
        };
        if (saveDlg.ShowDialog(this) == true)
        {
            byte[] backup = VeilProtocol.ExportEncryptedPrivateKey(ownId, passDlg.Value);
            File.WriteAllBytes(saveDlg.FileName, backup);
            StatusText.Text = $"Saved encrypted private key backup: {saveDlg.FileName}";
            MessageBox.Show(this, $"Encrypted private key backup saved to:\n{saveDlg.FileName}\n\nKeep this file private!",
                "Private Key Backed Up", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    private void ImportPrivateKey_Click(object sender, RoutedEventArgs e)
    {
        if (_manager.Vault == null) return;
        var dlg = new OpenFileDialog
        {
            Title = "Import Encrypted Private Key Backup (.veilkey)",
            Filter = "Veil Encrypted Private Key (*.veilkey)|*.veilkey|All Files (*.*)|*.*"
        };
        if (dlg.ShowDialog(this) != true) return;
        ImportPrivateKeyFile(dlg.FileName);
    }

    private void ImportPrivateKeyFile(string filePath)
    {
        var passDlg = new PromptDialog(
            "Decrypt Private Key Backup",
            $"Enter the backup passphrase for \"{Path.GetFileName(filePath)}\":",
            isPassword: true,
            okText: "Import Key") { Owner = this };

        if (passDlg.ShowDialog() != true) return;
        try
        {
            var id = _manager.ImportPrivateKey(File.ReadAllBytes(filePath), passDlg.Value);
            RefreshUI();
            MessageBox.Show(this,
                $"Imported Private + Public Key Pair:\n\nName: {id.DisplayName}\nKey ID: {id.ShortId}\nSafety Phrase: {id.SafetyPhrase}",
                "Private Key Imported", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Import Private Key Failed", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void ToggleVerify_Click(object sender, RoutedEventArgs e)
    {
        if (_manager.Vault == null) return;
        if (KeysGrid.SelectedItem is ContactEntry entry && !entry.HasPrivateKey)
        {
            var contact = _manager.Vault.Contacts.FirstOrDefault(c => c.FingerprintHex == entry.FingerprintHex);
            if (contact != null)
            {
                contact.Verified = !contact.Verified;
                _manager.Save();
                RefreshUI();
            }
        }
    }

    private void DeleteSelectedKey_Click(object sender, RoutedEventArgs e)
    {
        if (_manager.Vault == null || KeysGrid.SelectedItem is not ContactEntry entry) return;
        string warning = entry.HasPrivateKey
            ? $"Delete YOUR PRIVATE KEY \"{entry.DisplayName}\" ({entry.ShortId})?\n\nYou will no longer be able to decrypt .veil files encrypted to this key unless you have a .veilkey backup!"
            : $"Remove contact public key \"{entry.DisplayName}\" ({entry.ShortId})?";

        var res = MessageBox.Show(this, warning, "Confirm Delete", MessageBoxButton.YesNo,
            entry.HasPrivateKey ? MessageBoxImage.Warning : MessageBoxImage.Question);
        if (res != MessageBoxResult.Yes) return;

        try
        {
            _manager.DeleteKey(entry.FingerprintHex);
            RefreshUI();
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Cannot Delete Key", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void CtxEncryptForKey_Click(object sender, RoutedEventArgs e)
    {
        if (KeysGrid.SelectedItem is ContactEntry entry)
            SelectRecipientAndGoToEncrypt(entry);
    }

    private void GoToEncrypt_Click(object sender, RoutedEventArgs e)
    {
        MainTabs.SelectedIndex = 1;
        ComposeBox.Focus();
    }

    private void AttachFile_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog { Title = "Select File to Encrypt Inside .veil" };
        if (dlg.ShowDialog(this) == true) AttachFilePath(dlg.FileName);
    }

    private void AttachFilePath(string path)
    {
        bool strip = StripMetadataCheck?.IsChecked == true;
        bool stripped = false;
        byte[] bytes = strip && ImageSanitizer.IsSupportedImage(path)
            ? ImageSanitizer.StripMetadata(path, out stripped)
            : File.ReadAllBytes(path);

        string safeName = stripped
            ? $"image-{System.Security.Cryptography.RandomNumberGenerator.GetHexString(8, lowercase: true)}{Path.GetExtension(path).ToLowerInvariant()}"
            : Path.GetFileName(path);

        _pendingAttachment = new VeilAttachment
        {
            Name = safeName,
            Mime = "application/octet-stream",
            Size = bytes.Length,
            DataBase64 = Convert.ToBase64String(bytes),
        };
        string tag = stripped ? " — EXIF/GPS & filename anonymized" : "";
        AttachmentLabel.Text = $"{_pendingAttachment.Name} ({_pendingAttachment.Size:N0} bytes{tag})";
        ClearAttachBtn.Visibility = Visibility.Visible;
    }

    private void ClearAttach_Click(object sender, RoutedEventArgs e)
    {
        _pendingAttachment = null;
        AttachmentLabel.Text = "";
        ClearAttachBtn.Visibility = Visibility.Collapsed;
    }

    private void PassphraseMode_Changed(object sender, RoutedEventArgs e)
    {
        bool passMode = PassphraseModeCheck.IsChecked == true;
        KeyEncryptPanel.Visibility = passMode ? Visibility.Collapsed : Visibility.Visible;
        PassEncryptPanel.Visibility = passMode ? Visibility.Visible : Visibility.Collapsed;
    }

    private void ExportVeil_Click(object sender, RoutedEventArgs e)
    {
        if (_manager.Vault == null) return;
        bool passMode = PassphraseModeCheck.IsChecked == true;

        string text = ComposeBox.Text.Trim();
        if (string.IsNullOrEmpty(text) && _pendingAttachment == null)
        {
            MessageBox.Show(this, "Enter a message or attach a file to encrypt.", "Export .veil", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (passMode)
        {
            string pass = SharePassBox.Password;
            string confirm = SharePassConfirmBox.Password;
            if (string.IsNullOrEmpty(pass) || pass.Length < 4)
            {
                MessageBox.Show(this, "Enter a passphrase of at least 4 characters.", "Export .veil", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            if (pass != confirm)
            {
                MessageBox.Show(this, "Passphrases do not match.", "Export .veil", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            string passDefaultName = _pendingAttachment != null ? $"{_pendingAttachment.Name}.veil" : "sealed-passphrase.veil";
            var passSaveDlg = new SaveFileDialog
            {
                Title = "Export Passphrase-Encrypted Veil File (.veil)",
                FileName = passDefaultName,
                Filter = "Veil Sealed File (*.veil)|*.veil"
            };
            if (passSaveDlg.ShowDialog(this) != true) return;

            try
            {
                var sealedRes = VeilProtocol.SealWithPassphrase(pass, text, _pendingAttachment);
                File.WriteAllBytes(passSaveDlg.FileName, sealedRes.PacketBytes);
                ComposeBox.Clear();
                SharePassBox.Clear();
                SharePassConfirmBox.Clear();
                ClearAttach_Click(sender, e);
                StatusText.Text = $"Exported passphrase-encrypted {Path.GetFileName(passSaveDlg.FileName)} ({sealedRes.PacketBytes.Length:N0} bytes)";

                var show = MessageBox.Show(this,
                    $"Exported passphrase-encrypted file:\n{passSaveDlg.FileName}\n\nSize: {sealedRes.PacketBytes.Length:N0} bytes (Argon2id 64 MiB + AES-256-GCM)\n\nShow file in Windows Explorer?",
                    "Veil Export Complete", MessageBoxButton.YesNo, MessageBoxImage.Information);
                if (show == MessageBoxResult.Yes)
                    Process.Start("explorer.exe", $"/select,\"{passSaveDlg.FileName}\"");
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Encryption Failed", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            return;
        }

        var signer = _manager.ActiveIdentity;
        if (signer == null)
        {
            MessageBox.Show(this, "No active key set selected.", "Export .veil", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (RecipientCombo.SelectedItem is not ContactEntry recipient)
        {
            MessageBox.Show(this, "Select a recipient public key first (or import a contact's public key).", "Export .veil", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        string defaultName = _pendingAttachment != null
            ? $"{_pendingAttachment.Name}.veil"
            : $"message-for-{new string(recipient.DisplayName.Select(ch => char.IsLetterOrDigit(ch) ? ch : '_').ToArray())}.veil";

        var saveDlg = new SaveFileDialog
        {
            Title = "Export Sealed Veil File (.veil)",
            FileName = defaultName,
            Filter = "Veil Sealed File (*.veil)|*.veil"
        };
        if (saveDlg.ShowDialog(this) != true) return;

        try
        {
            var recipientCard = VeilProtocol.ParseContactCard(recipient.CardBase64);
            var sealedRes = VeilProtocol.SealEnvelope(signer, recipientCard, text, _pendingAttachment);
            File.WriteAllBytes(saveDlg.FileName, sealedRes.PacketBytes);

            ComposeBox.Clear();
            ClearAttach_Click(sender, e);
            StatusText.Text = $"Exported {Path.GetFileName(saveDlg.FileName)} ({sealedRes.PacketBytes.Length:N0} bytes)";

            var show = MessageBox.Show(this,
                $"Exported post-quantum sealed file:\n{saveDlg.FileName}\n\nSize: {sealedRes.PacketBytes.Length:N0} bytes (padded bucket: {sealedRes.PaddedInnerBytes:N0} B)\n\nShow file in Windows Explorer?",
                "Veil Export Complete", MessageBoxButton.YesNo, MessageBoxImage.Information);
            if (show == MessageBoxResult.Yes)
                Process.Start("explorer.exe", $"/select,\"{saveDlg.FileName}\"");
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Encryption Failed", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void DecryptFile_Click(object sender, RoutedEventArgs e)
    {
        if (_manager.Vault == null) return;
        var dlg = new OpenFileDialog
        {
            Title = "Open & Decrypt Veil File (.veil)",
            Filter = "Veil Sealed File (*.veil)|*.veil|All Files (*.*)|*.*"
        };
        if (dlg.ShowDialog(this) == true)
            DecryptVeilFile(dlg.FileName);
    }

    private void DecryptVeilFile(string filePath)
    {
        byte[] bytes = File.ReadAllBytes(filePath);
        string name = Path.GetFileName(filePath);
        try
        {
            if (VeilProtocol.IsPassphrasePacket(bytes))
            {
                var passDlg = new PromptDialog(
                    "Decrypt Passphrase-Protected .veil File",
                    $"Enter the shared passphrase for \"{name}\":",
                    isPassword: true,
                    okText: "Decrypt") { Owner = this };
                if (passDlg.ShowDialog() != true) return;

                var openedPass = VeilProtocol.OpenWithPassphrase(passDlg.Value, bytes);
                _lastDecrypted = openedPass;
                _lastDecryptedBytes = bytes;
                _lastDecryptedFileName = name;

                MainTabs.SelectedIndex = 1;
                DecStatusHeader.Text = $"Decrypted (Passphrase Mode): {name}";
                DecSenderLine.Text = "Encrypted with shared passphrase (no key pair)";
                DecMetaLine.Text = $"Sent: {openedPass.SentAt}  |  Argon2id (64 MiB) + AES-256-GCM";
                DecMessageBox.Text = string.IsNullOrEmpty(openedPass.Message) && openedPass.Attachment != null
                    ? $"[Decrypted Attachment Ready: {openedPass.Attachment.Name} ({openedPass.Attachment.Size:N0} bytes)]"
                    : openedPass.Message;

                BtnSaveDecAttachment.Visibility = openedPass.Attachment != null ? Visibility.Visible : Visibility.Collapsed;
                if (openedPass.Attachment != null)
                    BtnSaveDecAttachment.Content = $"Save Decrypted File ({openedPass.Attachment.Name})…";

                BtnAddSenderContact.Visibility = Visibility.Collapsed;
                BtnInspectDecPacket.Visibility = Visibility.Visible;
                StatusText.Text = $"Decrypted passphrase-protected file: {name}";
                return;
            }

            var (opened, activeKey) = _manager.DecryptWithActiveKey(bytes);
            _lastDecrypted = opened;
            _lastDecryptedBytes = bytes;
            _lastDecryptedFileName = name;

            MainTabs.SelectedIndex = 1;
            var knownContact = _manager.GetAllKeyRows().FirstOrDefault(c => c.FingerprintHex == opened.Sender.FingerprintHex);
            string trustNote = knownContact == null
                ? "New Sender (not yet in Contacts)"
                : (knownContact.HasPrivateKey ? "Your Key Set" : (knownContact.Verified ? "Verified Contact" : "Unverified Contact"));

            string sigSuite = opened.PostQuantumSignatureVerified
                ? "ML-KEM-768 + X25519  |  ML-DSA-65 + Ed25519 Verified"
                : "ML-KEM-768 + X25519  |  Ed25519 Verified (v1)";

            DecStatusHeader.Text = $"Decrypted & Verified: {name}";
            DecSenderLine.Text = $"Signed by: {opened.Sender.DisplayName}  [{opened.Sender.SafetyPhrase}]  —  {trustNote}";
            DecMetaLine.Text = $"Decrypted by active key set: {activeKey.DisplayName} ({activeKey.ShortId})  |  Sent: {opened.SentAt}  |  {sigSuite}";
            DecMessageBox.Text = string.IsNullOrEmpty(opened.Message) && opened.Attachment != null
                ? $"[Decrypted Attachment Ready: {opened.Attachment.Name} ({opened.Attachment.Size:N0} bytes)]"
                : opened.Message;

            BtnSaveDecAttachment.Visibility = opened.Attachment != null ? Visibility.Visible : Visibility.Collapsed;
            if (opened.Attachment != null)
                BtnSaveDecAttachment.Content = $"Save Decrypted File ({opened.Attachment.Name})…";

            BtnAddSenderContact.Visibility = knownContact == null ? Visibility.Visible : Visibility.Collapsed;
            BtnInspectDecPacket.Visibility = Visibility.Visible;
            StatusText.Text = $"Decrypted {name} — valid Ed25519 signature from {opened.Sender.DisplayName}";
        }
        catch (Exception ex)
        {
            var res = MessageBox.Show(this, $"{ex.Message}\n\nInspect this .veil packet in the Packet Inspector?",
                "Decryption Failed", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (res == MessageBoxResult.Yes)
                ShowInspection(bytes, name);
        }
    }

    private void SaveDecAttachment_Click(object sender, RoutedEventArgs e)
    {
        if (_lastDecrypted?.Attachment == null) return;
        var dlg = new SaveFileDialog
        {
            Title = "Save Decrypted Attachment",
            FileName = _lastDecrypted.Attachment.Name
        };
        if (dlg.ShowDialog(this) == true)
        {
            File.WriteAllBytes(dlg.FileName, Convert.FromBase64String(_lastDecrypted.Attachment.DataBase64));
            StatusText.Text = $"Saved decrypted file: {dlg.FileName}";
        }
    }

    private void AddSenderContact_Click(object sender, RoutedEventArgs e)
    {
        if (_lastDecrypted == null) return;
        try
        {
            var entry = _manager.ImportPublicKey(_lastDecrypted.Sender.CardBytes);
            BtnAddSenderContact.Visibility = Visibility.Collapsed;
            RefreshUI();
            MessageBox.Show(this, $"Added {entry.DisplayName} ({entry.SafetyPhrase}) to your Contacts.",
                "Contact Added", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Add Contact", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void InspectDecPacket_Click(object sender, RoutedEventArgs e)
    {
        if (_lastDecryptedBytes != null)
            ShowInspection(_lastDecryptedBytes, _lastDecryptedFileName);
    }

    private void InspectFile_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Title = "Inspect Veil Packet (.veil)",
            Filter = "Veil Sealed File (*.veil)|*.veil|All Files (*.*)|*.*"
        };
        if (dlg.ShowDialog(this) == true)
            ShowInspection(File.ReadAllBytes(dlg.FileName), Path.GetFileName(dlg.FileName));
    }

    private void ShowInspection(byte[] bytes, string label)
    {
        try
        {
            var info = VeilProtocol.InspectPacket(bytes);
            MainTabs.SelectedIndex = 2;
            InspectSummaryText.Text = $"Packet: {label}  ({info.TotalBytes:N0} bytes)  —  Protocol: {info.Protocol}";
            InspectWireMeta.Text = string.Join("   |   ", info.VisibleOnWire.Select(kv => $"{kv.Key}: {kv.Value}"));
            InspectTranscriptText.Text = $"HKDF Transcript Hash (SHA-256 of Outer Header): {info.TranscriptHashHex}";
            SegmentsGrid.ItemsSource = info.Segments;
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Packet Inspector", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void Window_DragOver(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop) ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    private void Window_Drop(object sender, DragEventArgs e)
    {
        if (!_manager.IsUnlocked || !e.Data.GetDataPresent(DataFormats.FileDrop)) return;
        var files = (string[])e.Data.GetData(DataFormats.FileDrop);
        if (files == null || files.Length == 0) return;

        string file = files[0];
        if (file.EndsWith(".veilpub", StringComparison.OrdinalIgnoreCase) || file.EndsWith(".veilcard", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                var entry = _manager.ImportPublicKey(File.ReadAllBytes(file));
                RefreshUI();
                MessageBox.Show(this, $"Verified & added contact public key:\n{entry.DisplayName} ({entry.SafetyPhrase})",
                    "Contact Added", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Import Failed", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        else if (file.EndsWith(".veilkey", StringComparison.OrdinalIgnoreCase))
        {
            ImportPrivateKeyFile(file);
        }
        else if (file.EndsWith(".veil", StringComparison.OrdinalIgnoreCase))
        {
            DecryptVeilFile(file);
        }
        else
        {
            AttachFilePath(file);
            MainTabs.SelectedIndex = 1;
            ComposeBox.Focus();
        }
    }

    private void LockVault_Click(object sender, RoutedEventArgs e)
    {
        _manager.Lock();
        _lastDecrypted = null;
        _lastDecryptedBytes = null;
        RefreshUI();
        EnsureUnlocked();
    }

    private void About_Click(object sender, RoutedEventArgs e)
    {
        MessageBox.Show(this,
            "Veil — Full Post-Quantum Hybrid Key & File Manager (VEIL-2)\n\n" +
            "• KEM: ML-KEM-768 (NIST FIPS 203) + X25519 Hybrid\n" +
            "• Signatures: Recipient-bound ML-DSA-65 (NIST FIPS 204) + Ed25519 Hybrid\n" +
            "• AEAD: AES-256-GCM with AAD-bound outer header & HKDF-SHA256 transcript\n" +
            "• Vault KDF: Argon2id (64 MiB, 3 iterations, 2 lanes) + 5-min Auto-Lock\n" +
            "• Privacy: Sealed sender, encrypted metadata, power-of-2 bucket padding\n" +
            "• Files: .veil (sealed), .veilpub (public keys), .veilkey (encrypted private key backups)",
            "About Veil", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void Exit_Click(object sender, RoutedEventArgs e) => Close();
}

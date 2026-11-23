using System;
using System.Windows;

namespace VeilDesktop.Dialogs;

public partial class VaultDialog : Window
{
    public bool IsCreateMode { get; }
    public string DisplayName => NameBox.Text.Trim();
    public string Passphrase => PassBox.Password;

    public Func<string, string, string?>? ValidateAction { get; set; }

    public VaultDialog(bool createMode)
    {
        InitializeComponent();
        IsCreateMode = createMode;
        if (createMode)
        {
            Title = "Create New Veil Vault";
            TitleText.Text = "Create New Key Pair & Vault";
            SubtitleText.Text = "Generates your decentralized ML-KEM-768 + ML-DSA-65 + X25519 + Ed25519 identity locally and encrypts your private keys at rest with Argon2id (64 MiB) + AES-256-GCM.";
            OkButton.Content = "Create Identity";
            NameBox.Text = Environment.UserName;
            NameBox.SelectAll();
            Loaded += (_, _) => NameBox.Focus();
        }
        else
        {
            Title = "Unlock Veil Vault";
            TitleText.Text = "Enter Vault Passphrase";
            SubtitleText.Text = "Decrypt your local Veil private keys.";
            NamePanel.Visibility = Visibility.Collapsed;
            OkButton.Content = "Unlock";
            Loaded += (_, _) => PassBox.Focus();
        }
    }

    private void OkButton_Click(object sender, RoutedEventArgs e)
    {
        ErrorText.Visibility = Visibility.Collapsed;
        if (IsCreateMode && string.IsNullOrWhiteSpace(DisplayName))
        {
            ShowError("Please enter a display name.");
            return;
        }
        if (string.IsNullOrEmpty(Passphrase) || (IsCreateMode && Passphrase.Length < 4))
        {
            ShowError(IsCreateMode ? "Passphrase must be at least 4 characters." : "Please enter your passphrase.");
            return;
        }

        if (ValidateAction != null)
        {
            string? err = ValidateAction(DisplayName, Passphrase);
            if (err != null)
            {
                ShowError(err);
                return;
            }
        }

        DialogResult = true;
    }

    private void ShowError(string msg)
    {
        ErrorText.Text = msg;
        ErrorText.Visibility = Visibility.Visible;
    }
}

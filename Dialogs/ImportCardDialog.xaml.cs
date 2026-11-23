using System.IO;
using System.Windows;
using Microsoft.Win32;

namespace VeilDesktop.Dialogs;

public partial class ImportCardDialog : Window
{
    public byte[]? SelectedFileBytes { get; private set; }
    public string? EnteredUri { get; private set; }

    public ImportCardDialog()
    {
        InitializeComponent();
        Loaded += (_, _) => UriBox.Focus();
    }

    private void Browse_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Title = "Import Veil Public Key",
            Filter = "Veil Public Key (*.veilpub;*.veilcard)|*.veilpub;*.veilcard|All Files (*.*)|*.*"
        };
        if (dlg.ShowDialog(this) == true)
        {
            SelectedFileBytes = File.ReadAllBytes(dlg.FileName);
            DialogResult = true;
        }
    }

    private void Ok_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(UriBox.Text))
        {
            MessageBox.Show(this, "Please paste a veilpub1:... public key or browse for a .veilpub file.",
                "Import Public Key", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        EnteredUri = UriBox.Text.Trim();
        DialogResult = true;
    }
}

using System.Windows;

namespace VeilDesktop.Dialogs;

public partial class PromptDialog : Window
{
    private readonly bool _isPassword;
    public string Value => _isPassword ? SecretBox.Password : InputBox.Text.Trim();

    public PromptDialog(string title, string label, bool isPassword = false, string? note = null, string okText = "OK")
    {
        InitializeComponent();
        _isPassword = isPassword;
        Title = title;
        PromptLabel.Text = label;
        OkBtn.Content = okText;

        if (isPassword)
        {
            InputBox.Visibility = Visibility.Collapsed;
            SecretBox.Visibility = Visibility.Visible;
            Loaded += (_, _) => SecretBox.Focus();
        }
        else
        {
            Loaded += (_, _) => InputBox.Focus();
        }

        if (!string.IsNullOrEmpty(note))
        {
            NoteText.Text = note;
            NoteText.Visibility = Visibility.Visible;
        }
    }

    private void Ok_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(Value))
        {
            MessageBox.Show(this, "Value cannot be empty.", Title, MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        DialogResult = true;
    }
}

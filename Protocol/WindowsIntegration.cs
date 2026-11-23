using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace VeilDesktop.Protocol;

public static class WindowsIntegration
{
    [DllImport("shell32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern void SHChangeNotify(int wEventId, uint uFlags, IntPtr dwItem1, IntPtr dwItem2);

    private const int ShcneAssocChanged = 0x08000000;
    private const uint ShcnfIdList = 0x0000;

    private static string GetExePath() =>
        Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule?.FileName ?? "";

    public static bool IsRegistered()
    {
        using var k = Registry.CurrentUser.OpenSubKey(@"Software\Classes\.veil");
        return k?.GetValue(null)?.ToString() == "Veil.Envelope";
    }

    public static void Register()
    {
        string exe = GetExePath();
        if (string.IsNullOrEmpty(exe)) throw new InvalidOperationException("Cannot locate Veil executable path.");

        RegisterExtension(".veil", "Veil.Envelope", "Veil Encrypted File", $"\"{exe}\" \"%1\"");
        RegisterExtension(".veilpub", "Veil.PublicKey", "Veil Public Key", $"\"{exe}\" \"%1\"");
        RegisterExtension(".veilkey", "Veil.PrivateKey", "Veil Encrypted Private Key Backup", $"\"{exe}\" \"%1\"");

        using (var shellKey = Registry.CurrentUser.CreateSubKey(@"Software\Classes\*\shell\EncryptWithVeil"))
        {
            shellKey.SetValue(null, "Encrypt with Veil");
            shellKey.SetValue("Icon", $"\"{exe}\",0");
            using var cmdKey = shellKey.CreateSubKey("command");
            cmdKey.SetValue(null, $"\"{exe}\" --encrypt \"%1\"");
        }

        SHChangeNotify(ShcneAssocChanged, ShcnfIdList, IntPtr.Zero, IntPtr.Zero);
    }

    public static void Unregister()
    {
        DeleteKeySafe(@"Software\Classes\.veil");
        DeleteKeySafe(@"Software\Classes\.veilpub");
        DeleteKeySafe(@"Software\Classes\.veilkey");
        DeleteKeySafe(@"Software\Classes\Veil.Envelope");
        DeleteKeySafe(@"Software\Classes\Veil.PublicKey");
        DeleteKeySafe(@"Software\Classes\Veil.PrivateKey");
        DeleteKeySafe(@"Software\Classes\*\shell\EncryptWithVeil");

        SHChangeNotify(ShcneAssocChanged, ShcnfIdList, IntPtr.Zero, IntPtr.Zero);
    }

    private static void RegisterExtension(string ext, string progId, string description, string openCommand)
    {
        using (var extKey = Registry.CurrentUser.CreateSubKey($@"Software\Classes\{ext}"))
        {
            extKey.SetValue(null, progId);
        }
        using (var progKey = Registry.CurrentUser.CreateSubKey($@"Software\Classes\{progId}"))
        {
            progKey.SetValue(null, description);
            using var cmdKey = progKey.CreateSubKey(@"shell\open\command");
            cmdKey.SetValue(null, openCommand);
        }
    }

    private static void DeleteKeySafe(string subKey)
    {
        try { Registry.CurrentUser.DeleteSubKeyTree(subKey, throwOnMissingSubKey: false); } catch { }
    }
}

using System;
using System.Windows;

namespace VeilDesktop;

public partial class App : Application
{
    public static string[] StartupArgs { get; private set; } = Array.Empty<string>();

    protected override void OnStartup(StartupEventArgs e)
    {
        StartupArgs = e.Args;
        base.OnStartup(e);
    }
}

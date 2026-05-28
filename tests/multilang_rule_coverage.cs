using System.Diagnostics;
using System.Security.Cryptography;

class MultiLangCSharpCoverage {
    void Run(string cmd) {
        Process.Start(cmd);
        MD5.Create();
    }

    // CSRF: ASP.NET Core action that bypasses antiforgery validation.
    [IgnoreAntiforgeryToken]
    public void Save() { }
}

using System.Diagnostics;
using System.Security.Cryptography;

class MultiLangCSharpCoverage {
    void Run(string cmd) {
        Process.Start(cmd);
        MD5.Create();
    }
}

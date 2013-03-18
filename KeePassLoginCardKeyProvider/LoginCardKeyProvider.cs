using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using KeePassLib.Keys;

namespace KeePassLoginCard
{
    public sealed class LoginCardKeyProvider : KeyProvider
    {
        public override string Name
        {
            get { return "LoginCard Key Provider"; }
        }

        public override byte[] GetKey(KeyProviderQueryContext ctx)
        {
            try
            {
                var path = Assembly.GetAssembly(typeof(LoginCardKeyProvider)).Location;
                path = Path.GetDirectoryName(path);
                var file = Path.Combine(path, @"KeePassLoginCard32.exe");

                if(!File.Exists(file))
                    throw new FileNotFoundException(file + " not found");

                var p = new Process
                            {
                                StartInfo =
                                    {
                                        FileName = file,
                                        Arguments = ctx.CreatingNewKey ? "1" : "0",
                                        UseShellExecute = false,
                                        RedirectStandardOutput = true,
                                    }
                            };

                p.Start();
                
                var output = p.StandardOutput.ReadToEnd();

                p.WaitForExit();

                if (output.StartsWith("Error:"))
                    throw new Exception(output.Substring(6));

                var enc = new UTF8Encoding();

                var key = enc.GetBytes(output);

                return key;
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Error");
                return null;
            }
        }
    }

}
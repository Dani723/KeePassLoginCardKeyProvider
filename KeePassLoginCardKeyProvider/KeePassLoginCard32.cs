using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Text;
using System.Windows.Forms;

namespace KeePassLoginCard32
{
    class Program
    {
        [STAThread]
        static void Main(string[] args)
        {
            try
            {
                if(args.Length < 1)
                    throw new Exception("Missing arg");

                int i;
                if(!int.TryParse(args[0], out i))
                    throw new Exception("Arg must be int");

                if(i==1)
                {
                    if (MessageBox.Show("Eine neue Datenbank wird erstellt/Das Passwort einer Datenbank wird geändert. Soll ein neuer Schlüssel generiert und auf die LoginCard geschrieben werden? Ein auf der Karte bereits vorhandener Schlüssel wird dadurch ungültig!", "KeePassLoginCard", 
                                        MessageBoxButtons.YesNo, MessageBoxIcon.Question, 
                                        MessageBoxDefaultButton.Button2) == DialogResult.Yes)
                    {

                        OiInitCard();

                        var pw = GeneratePw(50);

                        SaveToCard(pw);

                        if (MessageBox.Show("Soll eine Backup Key File erstellt werden? Diese Datei sollte extern gesichert werden.", "KeePassLoginCard",
                                            MessageBoxButtons.YesNo, MessageBoxIcon.Question,
                                            MessageBoxDefaultButton.Button2) == DialogResult.Yes)
                        {

                            var sfd = new SaveFileDialog
                                          {
                                              Title = "Save LoginCard Backup File",
                                              CheckFileExists = false,
                                              CheckPathExists = true,
                                              FileName = "LoginCardBackup",
                                              DefaultExt = "bin",
                                              Filter = "Bin files (*.bin)|*.bin|All files (*.*)|*.*"
                                          };

                            if (sfd.ShowDialog() == DialogResult.OK)
                            {
                                using (var binWriter = new BinaryWriter(File.Open(sfd.FileName, FileMode.Create)))
                                {
                                    var pw2 = LoadFromCard();

                                    var enc = new UTF8Encoding();
                                    var bytes = enc.GetBytes(pw2);
                                    binWriter.Write(bytes);
                                }                                
                            }

                        }
                    }
                }

                var s = LoadFromCard();
                Console.Write(s);
            }
            catch (Exception ex)
            {
                Console.Write("Error:" + ex.Message);
            }
        }



        public static string LoadFromCard()
        {
            var ref2 = new CMemRef
            {
                m_pData = Marshal.AllocHGlobal(0x400),
                m_nBufferLen = 0x400
            };

            var ref3 = ref2;
            uint code = OiReadFile(0x11, ref ref3);

            if (code != 0L)
            {
                var error = CardError(code);
                throw new Exception(error);
            }

            var s = Marshal.PtrToStringAnsi(ref2.m_pData, (int)ref2.m_nBufferLen).Substring(0, 0x3e8).TrimEnd(new char[0]);

            return s;
        }

        public static void SaveToCard(string text)
        {
            CMemRef ref2 = new CMemRef
            {
                m_pData = Marshal.AllocHGlobal(0x400),
                m_nBufferLen = 0x400
            };
            CMemRef ref3 = ref2;
            uint code = OiReadFile(0x11, ref ref3);
            if (code != 0L)
            {
                var error = CardError(code);
                throw new Exception(error);
            }
            string str = Marshal.PtrToStringAnsi(ref2.m_pData, (int)ref2.m_nBufferLen).Substring(0x3e8, 0x18);
            while (text.Length < 0x3e8)
            {
                text = text + " ";
            }
            ref2.m_pData = Marshal.StringToHGlobalAnsi(text + str);
            ref3 = ref2;
            code = OiWriteFile(0x11, ref ref3);
            if (code != 0L)
            {
                var error = CardError(code);
                throw new Exception(error);
            }
        }

        private static string GeneratePw(int length)
        {
            const string pwLetters = "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!\"$%&/()=?*#-";

            var pw = new StringBuilder();
            var rnd = new Random();

            for (int i = 0; i < length; i++)
                pw.Append(pwLetters[rnd.Next(pwLetters.Length)]);

            return pw.ToString();
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CMemRef
        {
            public IntPtr m_pData;
            public uint m_nBufferLen;
        }

        [DllImport("oi32.dll")]
        public static extern uint OiReadFile(byte p_nFileId, ref CMemRef p_pcData);
        [DllImport("oi32.dll")]
        public static extern uint OiWriteFile(byte p_nFileId, ref CMemRef p_pcData);
        [DllImport("oi32.dll")]
        public static extern uint OiInitCard();
        [DllImport("oi32.dll")]
        public static extern uint OiResetPassword();
        [DllImport("oi32.dll")]
        public static extern uint OiChangePassword();

        public static string CardError(uint code)
        {
            string str2 = "Unbekannter Fehlercode";
            switch (code)
            {
                case 0:
                    str2 = "OK";
                    break;

                case 1:
                    str2 = "Abbruch durch Benutzer";
                    break;

                case 2:
                    str2 = "Kein Kartenleser";
                    break;

                case 3:
                    str2 = "Netzwerkfehler";
                    break;

                case 4:
                    str2 = "Karte gesperrt";
                    break;

                case 5:
                    str2 = "Nicht registriert";
                    break;

                case 6:
                    str2 = "Deaktiviert";
                    break;

                case 10:
                    str2 = "PC/SC Connect";
                    break;

                case 11:
                    str2 = "PC/SC Transmit";
                    break;

                case 12:
                    str2 = "Anwendungsauswahl";
                    break;

                case 13:
                    str2 = "Authentifikation";
                    break;

                case 14:
                    str2 = "Schl\x00fcssel\x00e4nderung";
                    break;

                case 15:
                    str2 = "Erzeugen der Datendatei";
                    break;

                case 0x10:
                    str2 = "Lesen der Datendatei";
                    break;

                case 0x11:
                    str2 = "Schreiben der Datendatei";
                    break;

                case 0x12:
                    str2 = "Parameter";
                    break;

                case 0x13:
                    str2 = "Nicht initialisiert";
                    break;

                case 0x3e8:
                    str2 = "unbekannt";
                    break;
            }
            if (str2 == "OK")
            {
                return str2;
            }
            return str2;
        }
    }
}

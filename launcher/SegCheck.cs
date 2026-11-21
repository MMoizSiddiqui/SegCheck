// SegCheck launcher: double-click SegCheck.exe and SegCheck sets itself up, starts and opens in
// your browser.
//
// What it does:
//   1. If SegCheck is already running (on its port or one SegCheck moved to), it just opens the browser.
//   2. It picks the Python to use, in this order:
//        .venv\Scripts\python.exe       already set up from source
//        Python 3.11+ on this PC        first start from source (py launcher, PATH, usual folders)
//      If there is no Python 3.11+, it offers to install Python 3.12 for this user only with winget
//      (no administrator rights), or explains how to install it by hand.
//   3. It runs start_segcheck.py in a black "SegCheck" window. The first start creates .venv and
//      installs the packages (internet needed once), prepares the database and shows a one-time
//      setup token. If something goes wrong, the window stays open and lists the steps to fix it.
//      Close that window to stop SegCheck.
// Options are passed on, for example:  SegCheck.exe --port 5050
//
// Build (no extra tools needed; uses the C# compiler that ships with Windows):
//   python scripts/build_launcher.py

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;
using System.Windows.Forms;

static class SegCheckLauncher
{
    const string Title = "SegCheck";

    [STAThread]
    static int Main(string[] args)
    {
        Application.EnableVisualStyles();
        string root = AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\');
        int port = PortFrom(args);

        // Explorer runs an exe inside a ZIP from %TEMP%\Temp1_<name>.zip\... (short or long path form).
        bool insideZip = root.IndexOf(".zip\\", StringComparison.OrdinalIgnoreCase) >= 0 || root.EndsWith(".zip", StringComparison.OrdinalIgnoreCase);
        if (!File.Exists(Path.Combine(root, "start_segcheck.py")) && insideZip)
            return Fail("SegCheck.exe was opened from inside a ZIP file, so Windows unpacked only the exe.",
                "Close this message and the ZIP window.",
                "Right-click the downloaded ZIP > Extract All... and choose a folder such as C:\\SegCheck.",
                "Open the extracted folder and double-click SegCheck.exe there.");
        if (!File.Exists(Path.Combine(root, "start_segcheck.py")))
            return Fail("SegCheck.exe must stay inside the SegCheck folder.",
                "It needs start_segcheck.py and the other SegCheck files next to it (" + root + ").",
                "To put SegCheck on your desktop, right-click SegCheck.exe > Send to > Desktop (create shortcut) instead of moving it.");

        // Already running? Also look on the next ports: SegCheck moves there by itself when its port is taken.
        // Only ports something listens on are asked (a closed port costs ~1 s on Windows).
        var listening = ListeningPorts();
        for (int p = port; p <= port + 20; p++)
        {
            if (listening != null && !listening.Contains(p)) continue;
            string candidate = "http://127.0.0.1:" + p + "/";
            if (Running(candidate))
            {
                Process.Start(candidate);
                return 0;
            }
        }

        bool created;
        using (var mutex = new Mutex(true, "Local\\SegCheckLauncher-" + port, out created))
        {
            if (!created)
            {
                MessageBox.Show("SegCheck is already starting.\n\nLook for the black \"SegCheck\" window on the taskbar. " +
                    "The first start installs its packages and can take a few minutes; the browser opens by itself when it is ready.",
                    Title, MessageBoxButtons.OK, MessageBoxIcon.Information);
                return 0;
            }

            string python; List<string> pyArgs = new List<string>();
            // The private environment: next to SegCheck, or in the user's folder when SegCheck's own
            // folder is read-only (start_segcheck.py chooses; see _venv_location).
            string venv = Path.Combine(root, @".venv\Scripts\python.exe");
            if (!File.Exists(venv))
                venv = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"SegCheck\venv\Scripts\python.exe");
            if (File.Exists(venv) && Version(venv) >= 311)
            {
                python = venv;
            }
            else
            {
                python = FindPython();
                if (python == null) python = OfferInstall();
                if (python == null) return 1;
            }
            pyArgs.Add(Quote(Path.Combine(root, "start_segcheck.py")));
            foreach (string a in args) pyArgs.Add(Quote(a));

            // The window stays open only when SegCheck stopped with a problem, so the steps can be read.
            string command = "/c \"title SegCheck&& " + Quote(python) + " " + string.Join(" ", pyArgs.ToArray()) +
                " || (echo. & echo SegCheck stopped. Read the PROBLEM lines above for what to do. & pause)\"";
            var start = new ProcessStartInfo("cmd.exe", command) { UseShellExecute = true, WorkingDirectory = root };
            Process console;
            try { console = Process.Start(start); }
            catch (Exception ex)
            {
                return Fail("Windows could not open the SegCheck window: " + ex.Message,
                    "Try again. If it keeps happening, open a Command Prompt in this folder and run:",
                    "    " + Quote(python) + " start_segcheck.py");
            }
            if (console != null) console.WaitForExit();  // hold the mutex while SegCheck runs
        }
        return 0;
    }

    static int PortFrom(string[] args)
    {
        for (int i = 0; i < args.Length; i++)
        {
            int value;
            if (args[i] == "--port" && i + 1 < args.Length && int.TryParse(args[i + 1], out value)) return value;
            if (args[i].StartsWith("--port=") && int.TryParse(args[i].Substring(7), out value)) return value;
        }
        return 5000;
    }

    static HashSet<int> ListeningPorts()
    {
        try
        {
            var ports = new HashSet<int>();
            foreach (var endpoint in System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners())
                ports.Add(endpoint.Port);
            return ports;
        }
        catch { return null; }  // unknown: check every port
    }

    static bool Running(string url)
    {
        try
        {
            var request = (HttpWebRequest)WebRequest.Create(url + "api/health");
            request.Timeout = 800;
            request.Proxy = null;
            using (var response = (HttpWebResponse)request.GetResponse())
                return response.StatusCode == HttpStatusCode.OK && (response.Server ?? "").Contains("SegCheck");
        }
        catch (WebException ex)
        {
            var response = ex.Response as HttpWebResponse;  // a 503 from SegCheck still means it is running
            return response != null && (response.Server ?? "").Contains("SegCheck");
        }
        catch { return false; }
    }

    static string Quote(string value)
    {
        if (value.Length > 0 && value.IndexOfAny(new[] { ' ', '\t', '&', '(', ')', '^', '"' }) < 0) return value;
        return "\"" + value.Replace("\"", "\\\"") + "\"";
    }

    // Python version as 312 for 3.12, or 0 if it does not run.
    static int Version(string exe)
    {
        string output = Run(exe, "-c \"import sys; print(sys.version_info[0]*100+sys.version_info[1])\"");
        int value;
        return int.TryParse((output ?? "").Trim(), out value) ? value : 0;
    }

    static string Run(string exe, string arguments)
    {
        try
        {
            var info = new ProcessStartInfo(exe, arguments)
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true
            };
            using (var process = Process.Start(info))
            {
                string output = process.StandardOutput.ReadToEnd();
                if (!process.WaitForExit(20000)) { try { process.Kill(); } catch { } return null; }
                return process.ExitCode == 0 ? output : null;
            }
        }
        catch { return null; }
    }

    static string FindPython()
    {
        var candidates = new List<string>();
        string fromPy = Run("py", "-3 -c \"import sys; print(sys.executable)\"");  // the official py launcher
        if (!string.IsNullOrEmpty(fromPy)) candidates.Add(fromPy.Trim());
        foreach (string dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(';'))
        {
            if (dir.Trim().Length == 0 || dir.IndexOf("WindowsApps", StringComparison.OrdinalIgnoreCase) >= 0) continue;
            try { candidates.Add(Path.Combine(dir.Trim().Trim('"'), "python.exe")); } catch { }
        }
        foreach (string parent in new[] {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Programs\Python"),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles) })
        {
            try
            {
                string[] dirs = Directory.GetDirectories(parent, "Python3*");
                Array.Sort(dirs); Array.Reverse(dirs);  // newest first
                foreach (string dir in dirs) candidates.Add(Path.Combine(dir, "python.exe"));
            }
            catch { }
        }
        foreach (string exe in candidates)
            if (File.Exists(exe) && Version(exe) >= 311) return exe;
        return null;
    }

    static string OfferInstall()
    {
        var answer = MessageBox.Show(
            "SegCheck needs Python 3.11 or newer, and it is not installed on this PC.\n\n" +
            "Install Python 3.12 now?\n" +
            "  - Windows installs it for your account only (no administrator rights needed)\n" +
            "  - about 30 MB download, takes 1-3 minutes\n" +
            "  - by choosing Yes you accept the Python license and the winget source terms\n\n" +
            "Choose No to install it yourself from python.org (tick \"Add python.exe to PATH\").",
            Title, MessageBoxButtons.YesNo, MessageBoxIcon.Question);
        if (answer != DialogResult.Yes)
        {
            try { Process.Start("https://www.python.org/downloads/windows/"); } catch { }
            return null;
        }
        try
        {
            var install = Process.Start(new ProcessStartInfo("winget",
                "install --exact --id Python.Python.3.12 --scope user --accept-package-agreements --accept-source-agreements")
                { UseShellExecute = true });
            install.WaitForExit();
        }
        catch (Exception)
        {
            Fail("winget (Windows Package Manager) is not available on this PC.",
                "Install Python 3.12 from https://www.python.org/downloads/windows/ and tick \"Add python.exe to PATH\".",
                "Then double-click SegCheck.exe again.");
            try { Process.Start("https://www.python.org/downloads/windows/"); } catch { }
            return null;
        }
        string found = FindPython();
        if (found == null)
            Fail("Python was not found after the installation.",
                "If the installer window showed an error, install Python 3.12 from https://www.python.org/downloads/windows/ " +
                "and tick \"Add python.exe to PATH\".",
                "Then double-click SegCheck.exe again (sign out and in once if it is still not found).");
        return found;
    }

    static int Fail(string problem, params string[] steps)
    {
        var text = new StringBuilder(problem + "\n\nWhat to do:\n");
        for (int i = 0; i < steps.Length; i++) text.Append((i + 1) + ". " + steps[i] + "\n");
        MessageBox.Show(text.ToString(), Title, MessageBoxButtons.OK, MessageBoxIcon.Warning);
        return 1;
    }
}

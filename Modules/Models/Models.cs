﻿using Newtonsoft.Json;

namespace CryptoEat.Modules.Models;

public class Settings
{
    [JsonProperty("bruteLevel")] public int BruteLevel;
    [JsonProperty("strongBrute")] public bool StrongBrute;
    [JsonProperty("seedGrabber")] public bool SeedGrabber;
    [JsonProperty("scan")] public bool Scan;
    [JsonProperty("gpuBrute")] public bool GpuBrute;
    [JsonProperty("bruteTopPercent")] public int BruteTopPercent;
    [JsonProperty("balanceThreshold")] public decimal BalanceThreshold;
    [JsonProperty("scanDepth")] public int ScanDepth;
    [JsonProperty("proxyList")] public string? ProxyPath;
    [JsonProperty("proxyFormat")] public string? ProxyFormat;
    internal int BruteTopCount;
    internal bool AntipublicWorking = true;
}

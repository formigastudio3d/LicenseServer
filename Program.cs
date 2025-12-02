using System.Security.Cryptography;
using System.Text;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

const string Secret = "SuaChaveSecretaAqui"; // mesma chave do ManagerService
var issued = new Dictionary<string, DateTimeOffset>(); // memória simples

app.MapPost("/license/issue", (IssueRequest req) =>
{
    var exp = DateTimeOffset.UtcNow.AddDays(req.Days <= 0 ? 30 : req.Days);
    issued[req.HardwareId] = exp;
    var payload = System.Text.Json.JsonSerializer.Serialize(new LicenseTokenDto
    {
        HardwareId = req.HardwareId,
        ExpiresAt = exp,
        Source = req.Source ?? "license-server",
        MaxNodes = req.MaxNodes <= 0 ? 2 : req.MaxNodes
    });
    var token = $"{Convert.ToBase64String(Encoding.UTF8.GetBytes(payload))}.{Sign(payload)}";
    return Results.Ok(new { token, expiresAt = exp });
});

app.MapPost("/license/verify", (VerifyRequest req) =>
{
    if (!TryParse(req.Token, out var dto)) return Results.Json(new { valid = false, reason = "invalid" });
    if (dto.ExpiresAt <= DateTimeOffset.UtcNow) return Results.Json(new { valid = false, reason = "expired" });
    return Results.Ok(new { valid = true, dto.ExpiresAt, dto.Source, dto.MaxNodes });
});

app.Run();

static string Sign(string payload)
{
    using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(Secret));
    return Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(payload)));
}
static bool TryParse(string token, out LicenseTokenDto dto)
{
    dto = null!;
    var parts = token.Split('.', 2);
    if (parts.Length != 2) return false;
    var payload = Encoding.UTF8.GetString(Convert.FromBase64String(parts[0]));
    if (parts[1] != Sign(payload)) return false;
    dto = System.Text.Json.JsonSerializer.Deserialize<LicenseTokenDto>(payload)!;
    return dto != null && dto.ExpiresAt > DateTimeOffset.UtcNow;
}

record IssueRequest(string HardwareId, int Days, int MaxNodes, string? Source);
record VerifyRequest(string Token);
record LicenseTokenDto
{
    public string HardwareId { get; set; } = "";
    public DateTimeOffset ExpiresAt { get; set; }
    public string Source { get; set; } = "license-server";
    public int MaxNodes { get; set; } = 2;
}

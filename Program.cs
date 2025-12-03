using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Npgsql;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

var secret = Environment.GetEnvironmentVariable("LICENSE_SECRET") ?? "ReplaceWithYourSecretKey";
var dbUrl = Environment.GetEnvironmentVariable("DATABASE_URL") ?? "";
await EnsureTableAsync(dbUrl);

app.MapPost("/license/issue", async ([FromBody] LicenseRequest req) =>
{
    var connStr = BuildConn(dbUrl);
    await using var conn = new NpgsqlConnection(connStr);
    await conn.OpenAsync();

    var expiresAt = DateTimeOffset.UtcNow.AddDays(req.Days);
    var upsert = @"
        insert into licenses (hardware_id, expires_at, max_nodes, last_issued)
        values (@h, @e, @m, now())
        on conflict (hardware_id) do update
        set expires_at = excluded.expires_at,
            max_nodes = excluded.max_nodes,
            last_issued = now();";
    await using (var cmd = new NpgsqlCommand(upsert, conn))
    {
        cmd.Parameters.AddWithValue("h", req.HardwareId);
        cmd.Parameters.AddWithValue("e", expiresAt);
        cmd.Parameters.AddWithValue("m", req.MaxNodes);
        await cmd.ExecuteNonQueryAsync();
    }

    var dto = new LicenseTokenDto
    {
        HardwareId = req.HardwareId,
        ExpiresAt  = expiresAt,
        MaxNodes   = req.MaxNodes,
        Source     = "LicenseServer"
    };
    var token = IssueToken(dto, secret);
    return Results.Ok(new { token });
});

app.MapPost("/license/verify", async ([FromBody] LicenseToken token) =>
{
    var valid = await ValidateToken(token.Token, dbUrl, secret);
    return valid ? Results.Ok(new { valid = true }) : Results.BadRequest(new { message = "Token inválido" });
});

app.Run();

static string BuildConn(string url)
{
    if (string.IsNullOrWhiteSpace(url)) return "";
    // aceita postgres://user:pass@host:port/db
    var uri = new Uri(url);
    var userInfo = uri.UserInfo.Split(':', 2);
    var user = userInfo[0];
    var pass = userInfo.Length > 1 ? userInfo[1] : "";
    var port = uri.Port > 0 ? uri.Port : 5432;
    return $"Host={uri.Host};Port={port};Username={user};Password={pass};Database={uri.AbsolutePath.Trim('/')};Ssl Mode=Prefer;Trust Server Certificate=true";
}

static async Task EnsureTableAsync(string url)
{
    var connStr = BuildConn(url);
    await using var conn = new NpgsqlConnection(connStr);
    await conn.OpenAsync();
    var sql = @"
        create table if not exists licenses (
            hardware_id text primary key,
            expires_at timestamptz not null,
            max_nodes int not null,
            last_issued timestamptz not null
        );";
    await using var cmd = new NpgsqlCommand(sql, conn);
    await cmd.ExecuteNonQueryAsync();
}

static string IssueToken(LicenseTokenDto dto, string secret)
{
    var payloadJson = JsonSerializer.Serialize(dto);
    var payloadB64  = Convert.ToBase64String(Encoding.UTF8.GetBytes(payloadJson));
    var sig         = Sign(payloadJson, secret);
    return $"{payloadB64}.{sig}";
}

static string Sign(string data, string secret)
{
    using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
    var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
    return Convert.ToBase64String(hash);
}

static bool Verify(string data, string signature, string secret)
{
    var expected = Sign(data, secret);
    return CryptographicOperations.FixedTimeEquals(
        Encoding.UTF8.GetBytes(expected),
        Encoding.UTF8.GetBytes(signature));
}

static async Task<bool> ValidateToken(string token, string url, string secret)
{
    var parts = token.Split('.', 2);
    if (parts.Length != 2) return false;

    var payloadJson = Encoding.UTF8.GetString(Convert.FromBase64String(parts[0]));
    if (!Verify(payloadJson, parts[1], secret)) return false;

    var dto = JsonSerializer.Deserialize<LicenseTokenDto>(payloadJson);
    if (dto == null || dto.ExpiresAt <= DateTimeOffset.UtcNow) return false;

    var connStr = BuildConn(url);
    await using var conn = new NpgsqlConnection(connStr);
    await conn.OpenAsync();
    var sql = "select expires_at, max_nodes from licenses where hardware_id = @h";
    await using var cmd = new NpgsqlCommand(sql, conn);
    cmd.Parameters.AddWithValue("h", dto.HardwareId);
    await using var rd = await cmd.ExecuteReaderAsync();
    if (!await rd.ReadAsync()) return false;
    var expiresDb = rd.GetFieldValue<DateTimeOffset>(0);
    var maxDb     = rd.GetInt32(1);
    return expiresDb >= DateTimeOffset.UtcNow && dto.MaxNodes <= maxDb;
}

public record LicenseRequest(string HardwareId, int Days, int MaxNodes);
public record LicenseToken(string Token);
public class LicenseTokenDto
{
    public string HardwareId { get; set; } = "";
    public DateTimeOffset ExpiresAt { get; set; }
    public string Source { get; set; } = "";
    public int MaxNodes { get; set; }
}

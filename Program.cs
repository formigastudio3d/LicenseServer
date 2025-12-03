using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Npgsql;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// ----------------- Config -----------------
var secretKey = Environment.GetEnvironmentVariable("LICENSE_SECRET") ?? "ReplaceWithASecretKey";
var rawDbUrl  = Environment.GetEnvironmentVariable("DATABASE_URL")
               ?? throw new Exception("DATABASE_URL is not set");

// Converte postgres://user:pass@host:port/db para connection string Npgsql
string BuildConn(string rawUrl)
{
    var uri = new Uri(rawUrl);
    var userInfo = uri.UserInfo.Split(':', 2);
    var port = uri.Port > 0 ? uri.Port : 5432;

    var csb = new NpgsqlConnectionStringBuilder
    {
        Host = uri.Host,
        Port = port,
        Username = userInfo[0],
        Password = userInfo.Length > 1 ? userInfo[1] : "",
        Database = uri.AbsolutePath.TrimStart('/'),
        SslMode = SslMode.Require,
        TrustServerCertificate = true
    };
    return csb.ConnectionString;
}

var connString = BuildConn(rawDbUrl);

// ----------------- Models -----------------
record LicenseRequest(string HardwareId, int Days = 30, int MaxNodes = 2);
record LicenseToken(string Token);
record LicenseStatus(bool Valid, DateTime? ExpiresAt, int? MaxNodes, string? Message);

// ----------------- Helpers -----------------
async Task EnsureTableAsync()
{
    await using var conn = new NpgsqlConnection(connString);
    await conn.OpenAsync();
    var sql = """
        create table if not exists licenses (
            hardware_id text primary key,
            expires_at  timestamptz not null,
            max_nodes   int not null,
            last_issued timestamptz not null
        );
    """;
    await using var cmd = new NpgsqlCommand(sql, conn);
    await cmd.ExecuteNonQueryAsync();
}

string Sign(string payload)
{
    using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secretKey));
    var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(payload));
    return Convert.ToBase64String(hash);
}

bool Verify(string payload, string signature)
{
    var expected = Sign(payload);
    return CryptographicOperations.FixedTimeEquals(
        Convert.FromBase64String(expected),
        Convert.FromBase64String(signature));
}

string IssueToken(string hardwareId, DateTime expiresAt, int maxNodes)
{
    var payload = $"{hardwareId}|{expiresAt:o}|{maxNodes}";
    var sig = Sign(payload);
    return Convert.ToBase64String(Encoding.UTF8.GetBytes($"{payload}|{sig}"));
}

LicenseStatus ValidateToken(string token, string hardwareId)
{
    try
    {
        var raw = Encoding.UTF8.GetString(Convert.FromBase64String(token));
        var parts = raw.Split('|');
        if (parts.Length != 4) return new(false, null, null, "token malformado");

        var hw = parts[0];
        var exp = DateTime.Parse(parts[1]);
        var maxNodes = int.Parse(parts[2]);
        var sig = parts[3];

        var payload = $"{hw}|{exp:o}|{maxNodes}";
        if (!Verify(payload, sig)) return new(false, null, null, "assinatura inválida");
        if (!string.Equals(hw, hardwareId, StringComparison.OrdinalIgnoreCase))
            return new(false, null, null, "hardware diferente");
        if (DateTime.UtcNow > exp) return new(false, exp, maxNodes, "expirada");

        return new(true, exp, maxNodes, "ok");
    }
    catch
    {
        return new(false, null, null, "erro ao validar");
    }
}

// ----------------- Endpoints -----------------
app.MapGet("/", () => Results.Ok("LicenseServer ok"));

app.MapPost("/license/issue", async ([FromBody] LicenseRequest req) =>
{
    if (string.IsNullOrWhiteSpace(req.HardwareId))
        return Results.BadRequest("HardwareId obrigatório");

    await EnsureTableAsync();
    await using var conn = new NpgsqlConnection(connString);
    await conn.OpenAsync();

    DateTime? expiresAt = null;
    int? maxNodes = null;

    const string select = "select expires_at, max_nodes from licenses where hardware_id = @hw";
    await using (var cmd = new NpgsqlCommand(select, conn))
    {
        cmd.Parameters.AddWithValue("hw", req.HardwareId);
        await using var rdr = await cmd.ExecuteReaderAsync();
        if (await rdr.ReadAsync())
        {
            expiresAt = rdr.GetDateTime(0);
            maxNodes = rdr.GetInt32(1);
        }
    }

    if (expiresAt == null)
    {
        expiresAt = DateTime.UtcNow.AddDays(req.Days);
        maxNodes = req.MaxNodes;
        const string insert = """
            insert into licenses (hardware_id, expires_at, max_nodes, last_issued)
            values (@hw, @exp, @mx, now())
        """;
        await using var cmd = new NpgsqlCommand(insert, conn);
        cmd.Parameters.AddWithValue("hw", req.HardwareId);
        cmd.Parameters.AddWithValue("exp", expiresAt.Value);
        cmd.Parameters.AddWithValue("mx", maxNodes.Value);
        await cmd.ExecuteNonQueryAsync();
    }
    else
    {
        if (DateTime.UtcNow > expiresAt.Value)
            return Results.StatusCode(StatusCodes.Status402PaymentRequired);

        const string update = "update licenses set last_issued = now() where hardware_id = @hw";
        await using var cmd = new NpgsqlCommand(update, conn);
        cmd.Parameters.AddWithValue("hw", req.HardwareId);
        await cmd.ExecuteNonQueryAsync();
    }

    var token = IssueToken(req.HardwareId, expiresAt.Value, maxNodes!.Value);
    return Results.Ok(new LicenseToken(token));
});

app.MapPost("/license/verify", async ([FromBody] LicenseToken body, [FromQuery] string hardwareId) =>
{
    if (string.IsNullOrWhiteSpace(hardwareId))
        return Results.BadRequest("hardwareId obrigatório");

    await EnsureTableAsync();
    var status = ValidateToken(body.Token, hardwareId);
    if (!status.Valid) return Results.Ok(status);

    await using var conn = new NpgsqlConnection(connString);
    await conn.OpenAsync();
    const string sql = "select expires_at, max_nodes from licenses where hardware_id = @hw";
    await using var cmd = new NpgsqlCommand(sql, conn);
    cmd.Parameters.AddWithValue("hw", hardwareId);
    await using var rdr = await cmd.ExecuteReaderAsync();
    if (!await rdr.ReadAsync())
        return Results.Ok(new LicenseStatus(false, null, null, "hardware não encontrado"));

    var exp = rdr.GetDateTime(0);
    var mx = rdr.GetInt32(1);
    if (DateTime.UtcNow > exp)
        return Results.Ok(new LicenseStatus(false, exp, mx, "expirada"));

    return Results.Ok(new LicenseStatus(true, exp, mx, "ok"));
});

app.Run();

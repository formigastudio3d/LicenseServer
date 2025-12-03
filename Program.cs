using System.Security.Cryptography;
using System.Text;
using Npgsql;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

const string Secret = "SuaChaveSecretaAqui"; // MESMA do ManagerService
var connString = Environment.GetEnvironmentVariable("DATABASE_URL") ?? "";
if (string.IsNullOrWhiteSpace(connString)) throw new Exception("DATABASE_URL não configurada");

// Cria tabela de assinaturas
using (var conn = new NpgsqlConnection(connString))
{
    conn.Open();
    using var cmd = new NpgsqlCommand(@"
        CREATE TABLE IF NOT EXISTS licenses (
            hardware_id TEXT PRIMARY KEY,
            expires_at  TIMESTAMPTZ,
            max_nodes   INT,
            last_issued TIMESTAMPTZ
        );", conn);
    cmd.ExecuteNonQuery();
}

// Emite token se assinatura ativa
app.MapPost("/license/issue", async (IssueRequest req) =>
{
    await using var conn = new NpgsqlConnection(connString);
    await conn.OpenAsync();
    await using var tx = await conn.BeginTransactionAsync();

    var now = DateTimeOffset.UtcNow;
    DateTimeOffset expiresAtDb = DateTimeOffset.MinValue;
    int maxNodesDb = req.MaxNodes <= 0 ? 2 : req.MaxNodes;

    // busca assinatura
    await using (var cmd = new NpgsqlCommand("SELECT expires_at, max_nodes FROM licenses WHERE hardware_id=@h", conn, tx))
    {
        cmd.Parameters.AddWithValue("h", req.HardwareId);
        await using var reader = await cmd.ExecuteReaderAsync();
        if (await reader.ReadAsync())
        {
            expiresAtDb = reader.IsDBNull(0) ? DateTimeOffset.MinValue : reader.GetFieldValue<DateTimeOffset>(0);
            maxNodesDb = reader.IsDBNull(1) ? maxNodesDb : reader.GetInt32(1);
        }
    }

    if (expiresAtDb == DateTimeOffset.MinValue)
    {
        // novo hardware: define assinatura para 30 dias (ajuste conforme seu modelo de cobrança)
        expiresAtDb = now.AddDays(30);
    }

    if (expiresAtDb <= now)
    {
        await tx.RollbackAsync();
        return Results.StatusCode(402); // assinatura vencida
    }

    // Token com validade "days" (padrão 30)
    var tokenExp = now.AddDays(req.Days <= 0 ? 30 : req.Days);
    var token = BuildToken(req.HardwareId, tokenExp, maxNodesDb);

    // atualiza last_issued e max_nodes (não mexe no expires_at da assinatura)
    await using (var cmd = new NpgsqlCommand(@"
        INSERT INTO licenses (hardware_id, expires_at, max_nodes, last_issued)
        VALUES (@h, @exp, @max, @li)
        ON CONFLICT (hardware_id) DO UPDATE SET
            expires_at = EXCLUDED.expires_at,
            max_nodes = EXCLUDED.max_nodes,
            last_issued = EXCLUDED.last_issued;", conn, tx))
    {
        cmd.Parameters.AddWithValue("h", req.HardwareId);
        cmd.Parameters.AddWithValue("exp", expiresAtDb);
        cmd.Parameters.AddWithValue("max", maxNodesDb);
        cmd.Parameters.AddWithValue("li", now);
        await cmd.ExecuteNonQueryAsync();
    }

    await tx.CommitAsync();
    return Results.Ok(new { token, expiresAt = tokenExp });
});

// Verifica token e assinatura no DB
app.MapPost("/license/verify", async (VerifyRequest req) =>
{
    if (!TryParse(req.Token, out var dto)) return Results.Json(new { valid = false, reason = "invalid" });
    await using var conn = new NpgsqlConnection(connString);
    await conn.OpenAsync();
    DateTimeOffset expiresAtDb = DateTimeOffset.MinValue;
    await using

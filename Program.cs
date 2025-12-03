using System.Security.Cryptography;
using System.Text;
using Npgsql;

// ...

const string Secret = "SuaChaveSecretaAqui"; // mesma do ManagerService

var raw = Environment.GetEnvironmentVariable("DATABASE_URL");
if (string.IsNullOrWhiteSpace(raw)) throw new Exception("DATABASE_URL não configurada");

// Converte postgres://user:pass@host:port/db -> Npgsql connstring
NpgsqlConnectionStringBuilder BuildConn(string url)
{
    var uri = new Uri(url);
    var userInfo = uri.UserInfo.Split(':');
    return new NpgsqlConnectionStringBuilder
    {
        Host = uri.Host,
        Port = uri.Port,
        Username = userInfo[0],
        Password = userInfo.Length > 1 ? userInfo[1] : "",
        Database = uri.AbsolutePath.Trim('/'),
        SslMode = SslMode.Require,
        TrustServerCertificate = true
    };
}

var csb = BuildConn(raw);
var connString = csb.ToString();

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

// … (restante do código issue/verify igual)

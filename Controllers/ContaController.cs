
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using MySqlConnector;
using PETGO.Models;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Security.Claims;
using System.Threading.Tasks;

namespace PETGO.Controllers
{
    public class ContaController : Controller
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<ContaController> _logger;

        public ContaController(
            IConfiguration configuration,
            ILogger<ContaController> logger)
        {
            _configuration = configuration;
            _logger = logger;
        }

        // =====================================
        // LOGIN - GET
        // =====================================
        [HttpGet]
        public IActionResult Login(string? returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;

            return View(new LoginViewModel());
        }

        // =====================================
        // LOGIN - POST
        // =====================================

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(
            LoginViewModel model,
            string? returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            try
            {
                string connectionString =
                    _configuration.GetConnectionString("PetGo")
                    ?? throw new InvalidOperationException(
                        "Conexão PetGo não configurada."
                    );

                string email = model.Email.Trim().ToLowerInvariant();

                using var conexao = new MySqlConnection(connectionString);
                await conexao.OpenAsync();

                string sql = @"
            SELECT id, nome, email, senha
            FROM usuarios
            WHERE email = @email
            LIMIT 1";

                using var comando = new MySqlCommand(sql, conexao);

                comando.Parameters.AddWithValue("@email", email);

                using var reader = await comando.ExecuteReaderAsync();

                if (!await reader.ReadAsync())
                {
                    ModelState.AddModelError(
                        string.Empty,
                        "E-mail ou senha inválidos."
                    );

                    return View(model);
                }

                int id = reader.GetInt32("id");
                string nome = reader.GetString("nome");
                string emailBanco = reader.GetString("email");
                string senhaHash = reader.GetString("senha");

                await reader.CloseAsync();

                // Verificar a senha cadastrada
                if (!VerificarHashSenha(model.Password, senhaHash))
                {
                    ModelState.AddModelError(
                        string.Empty,
                        "E-mail ou senha inválidos."
                    );

                    return View(model);
                }

                // Criar identidade do usuário
                var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, id.ToString()),
            new Claim(ClaimTypes.Name, nome),
            new Claim(ClaimTypes.Email, emailBanco)
        };

                var identidade = new ClaimsIdentity(
                    claims,
                    CookieAuthenticationDefaults.AuthenticationScheme
                );

                var principal = new ClaimsPrincipal(identidade);

                var propriedades = new AuthenticationProperties
                {
                    IsPersistent = model.Lembrar
                };

                if (model.Lembrar)
                {
                    propriedades.ExpiresUtc =
                        DateTimeOffset.UtcNow.AddDays(30);
                }

                // Criar sessão autenticada
                await HttpContext.SignInAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    principal,
                    propriedades
                );

                TempData["Sucesso"] = $"Bem-vindo ao PETGO, {nome}!";

                // Redirecionar para a página solicitada
                if (!string.IsNullOrEmpty(returnUrl) &&
                    Url.IsLocalUrl(returnUrl))
                {
                    return Redirect(returnUrl);
                }

                return RedirectToAction("Index", "Home");
            }
            catch (MySqlException ex)
            {
                _logger.LogError(ex, "Erro ao realizar login.");

                ModelState.AddModelError(
                    string.Empty,
                    "Não foi possível acessar o banco de dados."
                );

                return View(model);
            }
        }


        private bool VerificarHashSenha(string senha, string hashArmazenado)
        {
            try
            {
                string[] partes = hashArmazenado.Split('$');

                if (partes.Length != 4 || partes[0] != "PBKDF2")
                    return false;

                if (!int.TryParse(partes[1], out int iteracoes) ||
                    iteracoes <= 0)
                    return false;

                byte[] salt = Convert.FromBase64String(partes[2]);
                byte[] hashOriginal = Convert.FromBase64String(partes[3]);

                byte[] hashCalculado = Rfc2898DeriveBytes.Pbkdf2(
                    senha,
                    salt,
                    iteracoes,
                    HashAlgorithmName.SHA256,
                    hashOriginal.Length
                );

                return CryptographicOperations.FixedTimeEquals(
                    hashCalculado,
                    hashOriginal
                );
            }
            catch (FormatException)
            {
                return false;
            }
        }


        // =====================================
        // CADASTRO - GET
        // =====================================
        [HttpGet]
        public IActionResult Cadastro()
        {
            return View("SignIn", new CadastroViewModel());
        }

        // =====================================
        // CADASTRO - POST
        // =====================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Cadastro(CadastroViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View("SignIn", model);
            }

            // Padronizar CPF e e-mail
            string cpf = Regex.Replace(
                model.CPF ?? "",
                @"\D",
                ""
            );

            string email = model.Email.Trim().ToLowerInvariant();

            // Validar CPF
            if (!ValidarCPF(cpf))
            {
                ModelState.AddModelError(
                    nameof(model.CPF),
                    "CPF inválido. Confira os números digitados."
                );

                return View("SignIn", model);
            }

            try
            {
                // Obter conexão
                string connectionString =
                    _configuration.GetConnectionString("PetGo")
                    ?? throw new InvalidOperationException(
                        "ConnectionString PetGo não encontrada no appsettings.json."
                    );

                using var conexao =
                    new MySqlConnection(connectionString);

                conexao.Open();

                // =====================================
                // VERIFICAR CPF DUPLICADO
                // =====================================
                using (var comandoCPF = new MySqlCommand(
                    "SELECT COUNT(*) FROM usuarios WHERE cpf = @cpf",
                    conexao))
                {
                    comandoCPF.Parameters.AddWithValue(
                        "@cpf",
                        cpf
                    );

                    int existeCPF = Convert.ToInt32(
                        comandoCPF.ExecuteScalar()
                    );

                    if (existeCPF > 0)
                    {
                        ModelState.AddModelError(
                            nameof(model.CPF),
                            "Este CPF já está cadastrado."
                        );

                        return View("SignIn", model);
                    }
                }

                // =====================================
                // VERIFICAR E-MAIL DUPLICADO
                // =====================================
                using (var comandoEmail = new MySqlCommand(
                    "SELECT COUNT(*) FROM usuarios WHERE email = @email",
                    conexao))
                {
                    comandoEmail.Parameters.AddWithValue(
                        "@email",
                        email
                    );

                    int existeEmail = Convert.ToInt32(
                        comandoEmail.ExecuteScalar()
                    );

                    if (existeEmail > 0)
                    {
                        ModelState.AddModelError(
                            nameof(model.Email),
                            "Este e-mail já está cadastrado."
                        );

                        return View("SignIn", model);
                    }
                }

                // =====================================
                // GERAR HASH DA SENHA
                // =====================================
                string senhaHash = GerarHashSenha(model.Senha);

                // =====================================
                // INSERIR USUÁRIO NO MYSQL
                // =====================================
                string sql = @"
                    INSERT INTO usuarios
                    (
                        nome,
                        cpf,
                        email,
                        telefone,
                        data_nascimento,
                        senha
                    )
                    VALUES
                    (
                        @nome,
                        @cpf,
                        @email,
                        @telefone,
                        @dataNascimento,
                        @senha
                    )";

                using var comando = new MySqlCommand(
                    sql,
                    conexao
                );

                comando.Parameters.AddWithValue(
                    "@nome",
                    model.Nome.Trim()
                );

                comando.Parameters.AddWithValue(
                    "@cpf",
                    cpf
                );

                comando.Parameters.AddWithValue(
                    "@email",
                    email
                );

                comando.Parameters.Add(
                    "@telefone",
                    MySqlDbType.VarChar
                ).Value = string.IsNullOrWhiteSpace(model.Telefone)
                    ? DBNull.Value
                    : model.Telefone.Trim();

                comando.Parameters.Add(
                    "@dataNascimento",
                    MySqlDbType.Date
                ).Value = model.DataNascimento.HasValue
                    ? (object)model.DataNascimento.Value.Date
                    : DBNull.Value;

                comando.Parameters.AddWithValue(
                    "@senha",
                    senhaHash
                );

                int linhasAfetadas = comando.ExecuteNonQuery();

                // =====================================
                // CADASTRO REALIZADO
                // =====================================
                if (linhasAfetadas > 0)
                {
                    _logger.LogInformation(
                        "Novo usuário cadastrado com sucesso. E-mail: {Email}",
                        email
                    );

                    TempData["Sucesso"] =
                        "Cadastro realizado com sucesso! Faça seu login.";

                    return RedirectToAction("Login");
                }

                ModelState.AddModelError(
                    string.Empty,
                    "Não foi possível realizar o cadastro."
                );
            }

            // =====================================
            // ERRO: CPF OU E-MAIL DUPLICADO
            // =====================================
            catch (MySqlException ex) when (ex.Number == 1062)
            {
                _logger.LogWarning(
                    ex,
                    "Tentativa de cadastro com CPF ou e-mail duplicado."
                );

                ModelState.AddModelError(
                    string.Empty,
                    "CPF ou e-mail já cadastrado."
                );
            }

            // =====================================
            // ERRO MYSQL
            // =====================================
            catch (MySqlException ex)
            {
                _logger.LogError(
                    ex,
                    "Erro MySQL ao realizar cadastro. Código: {Codigo}",
                    ex.Number
                );

                ModelState.AddModelError(
                    string.Empty,
                    "Erro ao conectar ou gravar os dados no banco. Consulte a saída do Visual Studio."
                );
            }

            // =====================================
            // ERRO GERAL
            // =====================================
            catch (Exception ex)
            {
                _logger.LogError(
                    ex,
                    "Erro inesperado ao realizar cadastro."
                );

                ModelState.AddModelError(
                    string.Empty,
                    "Ocorreu um erro inesperado ao realizar o cadastro."
                );
            }

            return View("SignIn", model);
        }

        // =====================================
        // VALIDAR CPF
        // =====================================
        private bool ValidarCPF(string cpf)
        {
            if (cpf.Length != 11)
                return false;

            if (cpf.All(c => c == cpf[0]))
                return false;

            int soma = 0;

            for (int i = 0; i < 9; i++)
            {
                soma += (cpf[i] - '0') * (10 - i);
            }

            int primeiroDigito = (soma * 10) % 11;

            if (primeiroDigito == 10)
                primeiroDigito = 0;

            if (primeiroDigito != cpf[9] - '0')
                return false;

            soma = 0;

            for (int i = 0; i < 10; i++)
            {
                soma += (cpf[i] - '0') * (11 - i);
            }

            int segundoDigito = (soma * 10) % 11;

            if (segundoDigito == 10)
                segundoDigito = 0;

            return segundoDigito == cpf[10] - '0';
        }

        // =====================================
        // HASH DA SENHA - PBKDF2
        // =====================================
        private string GerarHashSenha(string senha)
        {
            byte[] salt =
                RandomNumberGenerator.GetBytes(16);

            byte[] hash = Rfc2898DeriveBytes.Pbkdf2(
                senha,
                salt,
                210000,
                HashAlgorithmName.SHA256,
                32
            );

            return $"PBKDF2$210000${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
        }

        // =====================================
        // LOGOUT
        // =====================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(
                CookieAuthenticationDefaults.AuthenticationScheme
            );

            return RedirectToAction("Index", "Home");
        }
    }
}

using System.ComponentModel.DataAnnotations;

namespace PETGO.Models
{
    public class LoginViewModel
    {
        [Required(ErrorMessage = "Informe o e-mail ou utilizador.")]
        [EmailAddress(ErrorMessage = "Introduza um e-mail válido.")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "Informe a palavra-passe.")]
        [DataType(DataType.Password)]
        public string Password { get; set; } = string.Empty;

        public bool Lembrar { get; set; }
    }
}
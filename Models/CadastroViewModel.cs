
using System;
using System.ComponentModel.DataAnnotations;

namespace PETGO.Models
{
    public class CadastroViewModel
    {
        [Required(ErrorMessage = "Informe seu nome.")]
        [StringLength(150, ErrorMessage = "O nome deve ter no máximo 150 caracteres.")]
        public string Nome { get; set; } = string.Empty;

        [Required(ErrorMessage = "Informe seu CPF.")]
        [RegularExpression(
            @"^(\d{11}|\d{3}\.\d{3}\.\d{3}-\d{2})$",
            ErrorMessage = "Informe um CPF válido."
        )]
        public string CPF { get; set; } = string.Empty;

        [Required(ErrorMessage = "Informe seu e-mail.")]
        [EmailAddress(ErrorMessage = "Informe um e-mail válido.")]
        [StringLength(150)]
        public string Email { get; set; } = string.Empty;

        [StringLength(20)]
        public string? Telefone { get; set; }

        [Required(ErrorMessage = "Informe sua data de nascimento.")]
        [DataType(DataType.Date)]
        public DateTime? DataNascimento { get; set; }

        [Required(ErrorMessage = "Informe sua senha.")]
        [MinLength(8, ErrorMessage = "A senha deve ter pelo menos 8 caracteres.")]
        [StringLength(100)]
        [DataType(DataType.Password)]
        public string Senha { get; set; } = string.Empty;

        [Required(ErrorMessage = "Confirme sua senha.")]
        [Compare("Senha", ErrorMessage = "As senhas não coincidem.")]
        [DataType(DataType.Password)]
        public string ConfirmarSenha { get; set; } = string.Empty;
    }
}

using AspNetCore.Identity.MongoDbCore.Models;
using System.ComponentModel.DataAnnotations;

namespace Autenticacao.API.Model
{
    public class CreateUser
    {
        [Required]
        public string Name { get; set; }

        [Required]
        [EmailAddress(ErrorMessage = "Invalid Email")]
        public string Email { get; set; }

        [Required]
        public string Password { get; set; }
        public string UrlImagemPerfil { get; set; }
        public string UserRole { get; set; }
        [Required]
        public Guid CompanyId{ get; set; }

    }

    public class UpdateUser
    {
        [Required]
        public string Name { get; set; }
        [Required]
        public string Password { get; set; }

        [EmailAddress(ErrorMessage = "Invalid Email")]
        public string Email { get; set; }
        public string UrlImagemPerfil { get; set; }
        public string UserRole { get; set; }
    }

    public class ResetSenhaUser
    {
        [Required]
        public string Name { get; set; }
        [EmailAddress(ErrorMessage = "Invalid Email")]
        public string Email { get; set; }
        [Required]
        public string NewPassword { get; set; }
        public string Token { get; set; }

    }

    public class CreateAccount
    {
        [Required]

        public string Name { get; set; }

        [Required]
        public string Password { get; set; }
        /// <summary>
        /// CNPJ
        /// </summary>
        public string Cnpj { get; set; }

        /// <summary>
        /// Email
        /// </summary>
        [EmailAddress(ErrorMessage = "Invalid Email")]
        public string Email { get; set; }
        /// <summary>
        /// Telefone
        /// </summary>
        public string Telefone { get; set; }

        /// <summary>
        /// Url Image do Perfil
        /// </summary>
        public string UrlImage { get; set; }
    }
}

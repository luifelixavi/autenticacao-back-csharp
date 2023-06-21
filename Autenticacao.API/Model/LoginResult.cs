using System.ComponentModel.DataAnnotations;

namespace Autenticacao.API.Model
{
    public class LoginResult
    {
        public Guid Id { get; set; }
        public string UserName { get; set; }
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
        public string UrlImagemPerfil{ get; set; }
        public Guid CompanyId{ get; set; }
    }

    public class LoginRequest
    {
        [Required]
        public string Email { get; set; }
        [Required]
        public string Password { get; set; }


    }
}

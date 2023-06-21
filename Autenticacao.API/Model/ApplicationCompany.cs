using AspNetCore.Identity.MongoDbCore.Models;
using MongoDbGenericRepository.Attributes;

namespace Autenticacao.API.Model
{
    [CollectionName("ApplicationCompany")]
    public class ApplicationCompany : MongoIdentityUser<Guid>
    {

        public Guid Id { get; set; }

        /// <summary>
        /// CNPJ
        /// </summary>
        public string Cnpj { get; set; }

        /// <summary>
        /// Email
        /// </summary>
        public string Email { get; set; }
        /// <summary>
        /// Telefone
        /// </summary>
        public string Telefone { get; set; }

        /// <summary>
        /// Url Image do Perfil
        /// </summary>
        public string UrlImage { get; set; }

        /// <summary>
        /// Ativado?
        /// </summary>
        public bool Activated { get; set; }
    }
}

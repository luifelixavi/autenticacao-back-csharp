using AspNetCore.Identity.MongoDbCore.Models;
using MongoDB.Bson;
using MongoDbGenericRepository.Attributes;

namespace Autenticacao.API.Model
{
    [CollectionName("Users")]
    public class ApplicationUser : MongoIdentityUser<Guid>
    {
        public string UrlImagemPerfil { get; set; }
        public Guid CompanyId { get; set; }
        public string Cnpj { get; set; }
        public int Tipo { get; set; }
        public string TokenConfirmaEmail { get; set; }
    }
}

using Autenticacao.API.Model;
using Microsoft.AspNetCore.Identity;
using MongoDB.Driver;

namespace Autenticacao.API.Data
{
    /// <summary>
    /// The only service that directly interacts with MongoDB.
    /// </summary>
    public class IdentityServerService
    {
        private readonly IMongoCollection<ApplicationRole> _roles;
        private readonly IMongoCollection<ApplicationUser> _users;
        private readonly IMongoCollection<ApplicationUser> _accounts;
        private readonly IPasswordHasher<ApplicationUser> _passwordHasher;
        
        // private UserStore<ApplicationUser, ApplicationRole, ObjectId> UserStore { get; set; }

        public IdentityServerService(IPasswordHasher<ApplicationUser> passwordHasher)
        {
            var client = new MongoClient("ConnectionString");
            var database = client.GetDatabase("DatabaseName");

            _passwordHasher = passwordHasher;
            _users = database.GetCollection<ApplicationUser>("UsersCollectionName");
            _roles = database.GetCollection<ApplicationRole>("RolesCollectionName");
            _accounts = database.GetCollection<ApplicationUser>("AccountsCollectionName");
            //UserStore = new UserStore<ApplicationUser, ApplicationRole, Guid>(_users, _roles, new IdentityErrorDescriber());
        }

        /// <summary>
        /// Retrieves a user from MongoDB via username.
        /// </summary>
        /// <param name="userName"></param>
        /// <returns>User</returns>
        public ApplicationUser GetByUserName(string userName) => _users.Find(a => a.NormalizedUserName == userName.ToLower()).FirstOrDefault();

        /// <summary>
        /// Inserts a new user into MongoDB asynchronously
        /// </summary>
        /// <param name="account"></param>
        /// <returns></returns>
        //public async Task<IdentityResult> CreateAsync(ApplicationUser account) => .CreateAsync(account);

        /// <summary>
        /// Checks to see if a user is authorized with a given password.
        /// </summary>
        /// <param name="userName"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public bool IsAuthorized(string userName, string password)
        {
            var user = GetByUserName(userName);
            var verificationResult = _passwordHasher.VerifyHashedPassword(user, user.PasswordHash, password);

            return verificationResult == PasswordVerificationResult.Success;
        }
    }
}

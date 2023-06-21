using Autenticacao.API.Model;
using Microsoft.AspNetCore.Identity;
using System.Security.Cryptography;
using System.Text;

namespace Autenticacao.API.Data
{
    /// <summary>
    /// A service used to help securly store passwords in MongoDB.
    /// </summary>
    public class UserPasswordHasher : IPasswordHasher<ApplicationUser>
    {
        /// <summary>
        /// Hash a password for 
        /// </summary>
        /// <param name="user"></param>
        /// <param name="password"></param>
        /// <returns>string</returns>
        public string HashPassword(ApplicationUser user, string password)
        {
            using SHA256 mySHA256 = SHA256.Create();
            var hash = mySHA256.ComputeHash(Encoding.UTF8.GetBytes(password.ToString()));

            var hashSB = new StringBuilder();
            for (int i = 0; i < hash.Length; i++)
            {
                hashSB.Append(hash[i].ToString("x2"));
            }

            return hashSB.ToString();
        }

        /// <summary>
        /// Used in tandem with HashPassword() in order to check if a provided password matches the user's current password.
        /// </summary>
        /// <param name="user"></param>
        /// <param name="hashedPassword"></param>
        /// <param name="providedPassword"></param>
        /// <returns></returns>
        public PasswordVerificationResult VerifyHashedPassword(ApplicationUser user, string hashedPassword, string providedPassword)
        {
            return hashedPassword == HashPassword(user, providedPassword) ? PasswordVerificationResult.Success : PasswordVerificationResult.Failed;
        }
    }
}

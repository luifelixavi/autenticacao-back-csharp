using AspNetCore.Identity.MongoDbCore.Models;
using Autenticacao.API.Data;
using Autenticacao.API.Model;
using Core.Util.Email.Interface;
using Core.Util.Email.Service;
using DnsClient;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Specialized;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using System.Web;

namespace Autenticacao.API.Controllers
{
    [ApiController]
    [ApiConventionType(typeof(DefaultApiConventions))]
    [Route("api/account")]
    public class AccountController : Controller
    {

        private UserManager<ApplicationUser> userManager;
        private SignInManager<ApplicationUser> signInManager;
        private RoleManager<ApplicationRole> roleManager;
        private readonly JwtService jwtService;
        private readonly IEmailHelper emailHelper;
        public AccountController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            RoleManager<ApplicationRole> roleManager,
            JwtService jwtService,
            IEmailHelper emailHelper
            )
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.roleManager = roleManager;
            this.jwtService = jwtService;
            this.emailHelper = emailHelper;
        }


        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login(LoginRequest login)
        {
            if (ModelState.IsValid)
            {
                ApplicationUser appUser = await userManager.FindByEmailAsync(login.Email);
                if (appUser != null)
                {
                    Microsoft.AspNetCore.Identity.SignInResult result = await signInManager.PasswordSignInAsync(appUser, login.Password, false, false);

                    if (result.Succeeded)
                    {

                        if (appUser.EmailConfirmed == true)
                        {
                            var userLoged = new LoginResult()
                            {
                                UserName = appUser.UserName,
                                UrlImagemPerfil = appUser.UrlImagemPerfil,
                                CompanyId = appUser.CompanyId,
                                Id = appUser.Id
                            };

                            var claims = await userManager.GetClaimsAsync(appUser);

                            var jwtResult = this.jwtService.GenerateTokens(appUser.UserName, appUser.CompanyId.ToString(), appUser.Id.ToString(), claims, DateTime.Now);

                            userLoged.AccessToken = jwtResult.AccessToken;
                            userLoged.RefreshToken = jwtResult.RefreshToken.TokenString;

                            return Ok(userLoged);
                        }
                        else
                        {
                            return Unauthorized("Email não confirmado, por favor confirme primeiro");
                        }
                    }
                    else
                    {
                        return Unauthorized("Login falho: Email ou senha inválidos");
                    }
                }
                else
                {
                    return Unauthorized("Login falho: Email ou senha inválidos");
                }
            }
            return Ok();
        }

        //[Authorize]
        [HttpPost("create-role")]
        public async Task<IActionResult> CreateRole([Required] string name)
        {
            if (ModelState.IsValid)
            {
                IdentityResult result = await roleManager.CreateAsync(new ApplicationRole() { Name = name });

                if (result.Succeeded)
                    ViewBag.Message = "Role Created Successfully";
                else
                {
                    string errorResult = "";
                    foreach (IdentityError error in result.Errors)
                    {
                        errorResult += error.Description;

                    }
                    return BadRequest(errorResult);
                }
            }
            return Ok();
        }


        [HttpPost("login-google")]
        [AllowAnonymous]
        public async Task<IActionResult> GoogleLogin()
        {
            string redirectUrl = Url.Action("GoogleResponse", "Account");
            var properties = signInManager.ConfigureExternalAuthenticationProperties("Google", redirectUrl);
            return new ChallengeResult("Google", properties);
        }

        private async Task<IActionResult> GoogleResponse()
        {
            ExternalLoginInfo info = await signInManager.GetExternalLoginInfoAsync();
            if (info == null)
                return RedirectToAction(nameof(Login));

            var result = await signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, false);
            string[] userInfo = { info.Principal.FindFirst(ClaimTypes.Name).Value, info.Principal.FindFirst(ClaimTypes.Email).Value };
            if (result.Succeeded)
                return Ok(userInfo);
            else
            {
                ApplicationUser user = new ApplicationUser
                {
                    Email = info.Principal.FindFirst(ClaimTypes.Email).Value,
                    UserName = info.Principal.FindFirst(ClaimTypes.Email).Value
                };

                IdentityResult identResult = await userManager.CreateAsync(user);
                if (identResult.Succeeded)
                {
                    identResult = await userManager.AddLoginAsync(user, info);
                    if (identResult.Succeeded)
                    {
                        await signInManager.SignInAsync(user, false);
                        return Ok(userInfo);
                    }
                }
                return Unauthorized();
            }
        }

        [HttpPost("create-user")]
        public async Task<IActionResult> Create(CreateUser user)
        {

            if (ModelState.IsValid)
            {
                ApplicationUser appUser = new ApplicationUser
                {
                    Id = Guid.NewGuid(),
                    UserName = user.Name,
                    Email = user.Email,
                    UrlImagemPerfil = user.UrlImagemPerfil,
                    CompanyId = user.CompanyId
                };

                ApplicationUser account = await userManager.FindByIdAsync(user.CompanyId.ToString());

                if (account == null)
                {
                    return Conflict("Empresa não cadastrada, favor conferir o código enviado.");
                }
                IdentityResult result = await userManager.CreateAsync(appUser, user.Password);

                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(appUser, user.UserRole);
                    var token = await userManager.GenerateEmailConfirmationTokenAsync(appUser);


                    var confirmationLink = Url.Action(nameof(ConfirmEmail), "Account", new { token, email = user.Email }, Request.Scheme);


                    string message = "Por favor confirme sua conta clicando aqui <a href=\"" + confirmationLink + "\">here</a>";
                    //Send Email to User


                    //var confirmationLink = $"https://localhost:7278/api/account/confirm-email?code={code}&email={user.Email}";
                    //var message = $"Olá {user.Name}, confirme sua conta clicando neste link";
                    await this.emailHelper.SendEmail(appUser.Email, message);



                    return Ok("Foi enviado um email de confirmação para o email cadastrado, favor verifique sua caixa de email");
                }
                else
                {
                    return Conflict(result.Errors);
                }
            }
            return Ok();
        }

        [HttpPost("create-account")]
        public async Task<IActionResult> CreateAccount(CreateAccount account)
        {

            if (ModelState.IsValid)
            {
                Guid identificador = Guid.NewGuid();
                ApplicationUser appUser = new ApplicationUser
                {
                    Id = identificador,
                    UserName = account.Name.Replace(" ","_"),
                    Email = account.Email,
                    UrlImagemPerfil = account.UrlImage,
                    CompanyId = identificador,
                    Cnpj = account.Cnpj,
                    Tipo = 1
                };

                IdentityResult result = await userManager.CreateAsync(appUser, account.Password);

                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(appUser, "EMPRESA");
                    var token = await userManager.GenerateEmailConfirmationTokenAsync(appUser);
                    //var code = HttpUtility.UrlEncode(token);

                    //var confirmationLink = Url.Action("ConfirmEmail", "Email", new { token, email = user.Email }, Request.Scheme);

                    //var confirmationLink ="http://localhost:4200/#/confirma-email?token=" + token + "&email=" + account.Email;

                    var confirmationLink = Url.Action(nameof(ConfirmEmail), "Account", new { token, email = account.Email }, Request.Scheme);


                    string message = "Por favor confirme sua conta clicando  <a href=\"" + confirmationLink + "\">aqui</a>";
                    //Send Email to User

                    //var confirmationLink = $"https://localhost:7278/api/account/confirm-email?code={code}&email={user.Email}";
                    //var message = $"Olá {user.Name}, confirme sua conta clicando neste link";
                    await this.emailHelper.SendEmail(appUser.Email, message);

                    return Ok();
                }
                else
                {
                    return Conflict(result.Errors);
                }
            }
            else
            {
                return BadRequest();
            }
        }

        [HttpPost("update-user")]
        public async Task<IActionResult> Update(UpdateUser user)
        {

            if (ModelState.IsValid)
            {
                var userOld = await userManager.FindByEmailAsync(user.Email);
                if (userOld == null)
                    return Conflict("Erro, usuario não encontrado");

                ApplicationUser userNew = new ApplicationUser
                {
                    Id = userOld.Id,
                    UserName = user.Name,
                    Email = user.Email,
                    UrlImagemPerfil = user.UrlImagemPerfil
                };

                Microsoft.AspNetCore.Identity.SignInResult result = await signInManager.PasswordSignInAsync(userOld, user.Password, false, false);

                if (result.Succeeded)
                {
                    IdentityResult retornoUpdate = await userManager.UpdateAsync(userNew);

                    if (retornoUpdate.Succeeded)
                    {
                        await userManager.AddToRoleAsync(userNew, user.UserRole);
                        string message = "Sua conta na Barber Shop foi atualizada";
                        await this.emailHelper.SendEmail(userNew.Email, message);

                        return Ok("Foi enviado um email avisando sobre a atualizacao");
                    }
                    else
                    {
                        return Conflict(retornoUpdate.Errors);
                    }
                }
            }
            return Ok();
        }
        [HttpPost("confirma-reset-senha-user")]
        public async Task<IActionResult> ConfirmaResetSenha(ResetSenhaUser user)
        {
            if (ModelState.IsValid)
            {
                var userOld = await userManager.FindByEmailAsync(user.Email);
                if (userOld == null)
                    return Conflict("Erro, usuario não encontrado");

                ApplicationUser userNew = new ApplicationUser
                {
                    UserName = user.Name,
                    Email = user.Email
                };
                IdentityResult retornoUpdate = await userManager.ResetPasswordAsync(userNew, user.Token, user.NewPassword);

                if (retornoUpdate.Succeeded)
                {
                    string message = "Sua senha na Barber Shop foi trocada";
                    await this.emailHelper.SendEmail(userNew.Email, message);

                    return Ok("Foi enviado um email avisando sobre a mudança de senha");
                }
                else
                {
                    return Conflict(retornoUpdate.Errors);
                }
            }
            return Ok();
        }

        [HttpPost("reset-senha-user")]
        public async Task<IActionResult> ResetSenha(ResetSenhaUser user)
        {
            if (ModelState.IsValid)
            {
                var userOld = await userManager.FindByEmailAsync(user.Email);
                if (userOld == null)
                    return Conflict("Erro, usuario não encontrado");

                string token = await userManager.GeneratePasswordResetTokenAsync(userOld);


                var confirmationLink = Url.Action(nameof(ConfirmaResetSenha), "Account", new { token, email = user.Email }, Request.Scheme);


                string message = "Por favor confirme sua conta clicando aqui <a href=\"" + confirmationLink + "\">here</a>";

                await this.emailHelper.SendEmail(userOld.Email, message);

                return Ok("Foi enviado um email avisando sobre a mudança de senha");

            }
            return Ok();
        }

        private string ToQueryString(NameValueCollection nvc)
        {
            var array = (
                from key in nvc.AllKeys
                from value in nvc.GetValues(key)
                select string.Format(
            "{0}",

            HttpUtility.UrlEncode(value))
                ).ToArray();
            return "/" + string.Join("/", array);
        }

        [HttpGet("confirm-email")]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            var user = await userManager.FindByEmailAsync(email);
            if (user == null)
                return Conflict("Erro, usuario não encontrado");

            var result = await userManager.ConfirmEmailAsync(user, token);

            if (result.Succeeded)
            {
                return Ok();
            }
            else
            {
                return Conflict(result.Errors);
            }
        }
        /// <summary>
        /// Used for extending the life of an access token with the previously received refreshToken.
        /// </summary>
        /// <param name="refreshToken"></param>
        /// <returns>IActionResult</returns>
        [Authorize(AuthenticationSchemes = "Bearer")]
        [HttpPost("refresh-token")]
        public IActionResult RefreshToken([FromBody] string refreshToken)
        {
            try
            {
                var userName = User.Identity.Name;

                if (!string.IsNullOrWhiteSpace(refreshToken))
                {
                    var accessToken = HttpContext.GetTokenAsync("Bearer", "access_token").Result;
                    var jwtResult = jwtService.Refresh(refreshToken, userName, accessToken, DateTime.Now);

                    return Ok(new LoginResult
                    {
                        UserName = userName,
                        AccessToken = jwtResult.AccessToken,
                        RefreshToken = jwtResult.RefreshToken.TokenString
                    });
                }
            }
            catch (SecurityTokenException e)
            {
                return Unauthorized(e.Message);
            }

            return BadRequest();
        }
    }
}

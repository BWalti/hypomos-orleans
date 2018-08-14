namespace Webapp.Account
{
    using System.Net;
    using System.Security.Claims;
    using System.Threading.Tasks;
    using IdentityServer4.Services;
    using IdentityServer4.Stores;
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.Extensions.Logging;
    using Webapp.Controllers;
    using Webapp.Helpers;
    using Webapp.Identity;
    using Webapp.Models;

    [Authorize]
    [Route("[controller]/[action]")]
    public class AccountController : Controller
    {
        private readonly IUserClaimsPrincipalFactory<ApplicationUser> claimsPrincipalFactory;

        // private readonly IIdentityServerInteractionService interaction;
        private readonly IClientStore clientStore;
        private readonly IEventService events;
        private readonly IIdentityServerInteractionService interaction;

        private readonly ILogger logger;

        // private readonly AccountService _account;
        private readonly IAuthenticationSchemeProvider schemeProvider;
        private readonly SignInManager<ApplicationUser> signInManager;
        private readonly UserManager<ApplicationUser> userManager;

        public AccountController(
            IIdentityServerInteractionService interaction,
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            ILoggerFactory loggerFactory,
            IAuthenticationSchemeProvider schemeProvider,
            IUserClaimsPrincipalFactory<ApplicationUser> claimsPrincipalFactory,
            IEventService events,
            IClientStore clientStore)
        {
            this.interaction = interaction;
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.logger = loggerFactory.CreateLogger<AccountController>();
            this.schemeProvider = schemeProvider;
            this.claimsPrincipalFactory = claimsPrincipalFactory;
            this.events = events;
            this.clientStore = clientStore;

            // _account = new AccountService(interaction, httpContext, clientStore);
        }

        //
        // POST: /Account/Login
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        [ProducesResponseType(typeof(LoginModel), 200)]
        [ProducesResponseType(typeof(LoginModel), 400)]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            // Hack to work around rc1 bug
            await this.HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            if (!this.ModelState.IsValid)
            {
                return this.BadRequest(this.ModelState.AsApiModel(model));
            }

            var result =
                await this.signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberLogin, true);
            if (result.Succeeded)
            {
                this.logger.LogInformation(1, "User logged in.");
                return this.Ok(ApiModel.AsSuccess(model));
            }

            this.logger.LogWarning(2, "User login failed.");
            model.IsLockedOut = result.IsLockedOut;
            model.IsNotAllowed = result.IsNotAllowed;
            model.RequiresTwoFactor = result.RequiresTwoFactor;
            return this.BadRequest(ApiModel.AsError(model, "Login failed"));
        }

        /// <summary>
        ///     Handle logout page postback
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]

        // [AllowAnonymous]
        public async Task<IActionResult> Logout(LogoutInputModel model)
        {
            var user = this.HttpContext.User;
            if (user?.Identity.IsAuthenticated == true)
            {
                // delete local authentication cookie
                await this.signInManager.SignOutAsync();

                // await HttpContext.SignOutAsync();

                // raise the logout event
                // await this.events.RaiseAsync(new UserLogoutSuccessEvent(user.GetSubjectId(), user.GetName()));
            }

            return this.Ok("logged_out");
        }

        //
        // POST: /Account/ExternalLogin
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public IActionResult ExternalLogin(string provider, string returnUrl = null)
        {
            // Request a redirect to the external login provider.
            var redirectUrl = this.Url.Action("ExternalLoginCallback", "Account", new {ReturnUrl = returnUrl});
            var properties = this.signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
            return this.Challenge(properties, provider);
        }

        //
        // GET: /Account/ExternalLoginCallback
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ExternalLoginCallback(string returnUrl = null, string remoteError = null)
        {
            if (remoteError != null)
            {
                this.ModelState.AddModelError(string.Empty, $"Error from external provider: {remoteError}");
                return this.View(nameof(this.Login));
            }

            var info = await this.signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return this.RedirectToAction(nameof(this.Login));
            }

            // Sign in the user with this external login provider if the user already has a login.
            var result = await this.signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, false);
            if (result.Succeeded)
            {
                this.logger.LogInformation(5, "User logged in with {Name} provider.", info.LoginProvider);
                return this.RedirectToLocal(returnUrl);
            }

            //if (result.RequiresTwoFactor)
            //{
            //    return RedirectToAction(nameof(SendCode), new { ReturnUrl = returnUrl });
            //}
            if (result.IsLockedOut)
            {
                return this.View("Lockout");
            }

            // If the user does not have an account, then ask the user to create an account.
            this.ViewData["ReturnUrl"] = returnUrl;
            this.ViewData["LoginProvider"] = info.LoginProvider;
            var email = info.Principal.FindFirstValue(ClaimTypes.Email);
            return this.View("ExternalLoginConfirmation", new ExternalLoginConfirmationViewModel {Email = email});
        }

        //
        // POST: /Account/Register
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        [ProducesResponseType(typeof(RegisterModel), 200)]
        [ProducesResponseType(typeof(RegisterModel), 400)]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            if (!this.ModelState.IsValid)
            {
                return this.BadRequest(this.ModelState.AsApiModel(model));
            }

            var user = new ApplicationUser {UserName = model.Email, Email = model.Email};
            var result = await this.userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
            {
                return this.BadRequest(result.AsApiModel(model));
            }

            // For more information on how to enable account confirmation and password reset please visit http://go.microsoft.com/fwlink/?LinkID=532713
            // Send an email with this link
            //var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            //var callbackUrl = Url.Action("ConfirmEmail", "Account", new { userId = user.Id, code = code }, protocol: HttpContext.Request.Scheme);
            //await _emailSender.SendEmailAsync(model.Email, "Confirm your account",
            //    $"Please confirm your account by clicking this link: <a href='{callbackUrl}'>link</a>");
            await this.signInManager.SignInAsync(user, true);
            this.logger.LogInformation(3, "User created a new account with password.");

            //var tokens = this.antiForgery.GetAndStoreTokens(this.HttpContext);
            //if (!string.IsNullOrWhiteSpace(tokens.RequestToken))
            //{
            //    var cookieOptions = new CookieOptions
            //    {
            //        HttpOnly = false,
            //        Secure = this.Request.IsHttps
            //    };
            //    this.Response.Cookies.Append(Constants.AntiForgeryCookieName, tokens.RequestToken, cookieOptions);
            //}

            return this.Ok(ApiModel.AsSuccess<RegisterModel>(null));
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> GetUser()
        {
            UserModel userModel;

            // var userManager = this.serviceProvider.GetService<UserManager<ApplicationUser>>();
            if (this.User.Identity.IsAuthenticated)
            {
                var user = await this.userManager.FindByIdAsync(this.User.Identity.Name);
                userModel = new UserModel
                {
                    IsAuthenticated = true,
                    UserId = user.UserId,
                    Email = user.Email,
                    FirstName = user.PersonalData?.FirstName,
                    LastName = user.PersonalData?.LastName
                };
            }
            else
            {
                userModel = new UserModel
                {
                    IsAuthenticated = false
                };
            }

            return this.Ok(userModel);
        }

        //
        // POST: /Account/ExternalLoginConfirmation
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ExternalLoginConfirmation(ExternalLoginConfirmationViewModel model,
            string returnUrl = null)
        {
            if (this.ModelState.IsValid)
            {
                // Get the information about the user from the external login provider
                var info = await this.signInManager.GetExternalLoginInfoAsync();
                if (info == null)
                {
                    return this.View("ExternalLoginFailure");
                }

                var user = new ApplicationUser {UserName = model.Email, Email = model.Email};
                var result = await this.userManager.CreateAsync(user);
                if (result.Succeeded)
                {
                    result = await this.userManager.AddLoginAsync(user, info);
                    if (result.Succeeded)
                    {
                        await this.signInManager.SignInAsync(user, false);
                        this.logger.LogInformation(6, "User created an account using {Name} provider.",
                            info.LoginProvider);
                        return this.RedirectToLocal(returnUrl);
                    }
                }

                this.AddErrors(result);
            }

            this.ViewData["ReturnUrl"] = returnUrl;
            return this.View(model);
        }

        // GET: /Account/ConfirmEmail
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail(string userId, string code)
        {
            if ((userId == null) || (code == null))
            {
                return this.View("Error");
            }

            var user = await this.userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return this.View("Error");
            }

            var result = await this.userManager.ConfirmEmailAsync(user, code);
            return this.View(result.Succeeded ? "ConfirmEmail" : "Error");
        }

        //
        // GET: /Account/ForgotPassword
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPassword()
        {
            return this.View();
        }

        //
        // POST: /Account/ForgotPassword
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (this.ModelState.IsValid)
            {
                var user = await this.userManager.FindByNameAsync(model.Email);
                if ((user == null) || !await this.userManager.IsEmailConfirmedAsync(user))
                {
                    // Don't reveal that the user does not exist or is not confirmed
                    return this.View("ForgotPasswordConfirmation");
                }

                // For more information on how to enable account confirmation and password reset please visit http://go.microsoft.com/fwlink/?LinkID=532713
                // Send an email with this link
                //var code = await _userManager.GeneratePasswordResetTokenAsync(user);
                //var callbackUrl = Url.Action("ResetPassword", "Account", new { userId = user.Id, code = code }, protocol: HttpContext.Request.Scheme);
                //await _emailSender.SendEmailAsync(model.Email, "Reset Password",
                //   $"Please reset your password by clicking here: <a href='{callbackUrl}'>link</a>");
                //return View("ForgotPasswordConfirmation");
            }

            // If we got this far, something failed, redisplay form
            return this.View(model);
        }

        //
        // GET: /Account/ForgotPasswordConfirmation
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPasswordConfirmation()
        {
            return this.View();
        }

        //
        // GET: /Account/ResetPassword
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPassword(string code = null)
        {
            return code == null ? this.View("Error") : this.View();
        }

        //
        // POST: /Account/ResetPassword
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!this.ModelState.IsValid)
            {
                return this.View(model);
            }

            var user = await this.userManager.FindByNameAsync(model.Email);
            if (user == null)
            {
                // Don't reveal that the user does not exist
                return this.RedirectToAction(nameof(this.ResetPasswordConfirmation), "Account");
            }

            var result = await this.userManager.ResetPasswordAsync(user, model.Code, model.Password);
            if (result.Succeeded)
            {
                return this.RedirectToAction(nameof(this.ResetPasswordConfirmation), "Account");
            }

            this.AddErrors(result);
            return this.View();
        }

        //
        // GET: /Account/ResetPasswordConfirmation
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPasswordConfirmation()
        {
            return this.View();
        }

        //
        // GET: /Account/SendCode
        //[HttpGet]
        //[AllowAnonymous]
        //public async Task<ActionResult> SendCode(string returnUrl = null, bool rememberMe = false)
        //{
        //    var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
        //    if (user == null)
        //    {
        //        return View("Error");
        //    }
        //    var userFactors = await _userManager.GetValidTwoFactorProvidersAsync(user);
        //    var factorOptions = userFactors.Select(purpose => new SelectListItem { Text = purpose, Value = purpose }).ToList();
        //    return View(new SendCodeViewModel { Providers = factorOptions, ReturnUrl = returnUrl, RememberMe = rememberMe });
        //}

        ////
        //// POST: /Account/SendCode
        //[HttpPost]
        //[AllowAnonymous]
        //[ValidateAntiForgeryToken]
        //public async Task<IActionResult> SendCode(SendCodeViewModel model)
        //{
        //    if (!ModelState.IsValid)
        //    {
        //        return View();
        //    }

        //    var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
        //    if (user == null)
        //    {
        //        return View("Error");
        //    }

        //    // Generate the token and send it
        //    var code = await _userManager.GenerateTwoFactorTokenAsync(user, model.SelectedProvider);
        //    if (string.IsNullOrWhiteSpace(code))
        //    {
        //        return View("Error");
        //    }

        //    var message = "Your security code is: " + code;
        //    if (model.SelectedProvider == "Email")
        //    {
        //        await _emailSender.SendEmailAsync(await _userManager.GetEmailAsync(user), "Security Code", message);
        //    }
        //    else if (model.SelectedProvider == "Phone")
        //    {
        //        await _smsSender.SendSmsAsync(await _userManager.GetPhoneNumberAsync(user), message);
        //    }

        //    return RedirectToAction(nameof(VerifyCode), new { Provider = model.SelectedProvider, ReturnUrl = model.ReturnUrl, RememberMe = model.RememberMe });
        //}

        ////
        //// GET: /Account/VerifyCode
        //[HttpGet]
        //[AllowAnonymous]
        //public async Task<IActionResult> VerifyCode(string provider, bool rememberMe, string returnUrl = null)
        //{
        //    // Require that the user has already logged in via username/password or external login
        //    var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
        //    if (user == null)
        //    {
        //        return View("Error");
        //    }
        //    return View(new VerifyCodeViewModel { Provider = provider, ReturnUrl = returnUrl, RememberMe = rememberMe });
        //}

        ////
        //// POST: /Account/VerifyCode
        //[HttpPost]
        //[AllowAnonymous]
        //[ValidateAntiForgeryToken]
        //public async Task<IActionResult> VerifyCode(VerifyCodeViewModel model)
        //{
        //    if (!ModelState.IsValid)
        //    {
        //        return View(model);
        //    }

        //    // The following code protects for brute force attacks against the two factor codes.
        //    // If a user enters incorrect codes for a specified amount of time then the user account
        //    // will be locked out for a specified amount of time.
        //    var result = await _signInManager.TwoFactorSignInAsync(model.Provider, model.Code, model.RememberMe, model.RememberBrowser);
        //    if (result.Succeeded)
        //    {
        //        return RedirectToLocal(model.ReturnUrl);
        //    }
        //    if (result.IsLockedOut)
        //    {
        //        _logger.LogWarning(7, "User account locked out.");
        //        return View("Lockout");
        //    }
        //    else
        //    {
        //        ModelState.AddModelError(string.Empty, "Invalid code.");
        //        return View(model);
        //    }
        //}

        #region Helpers

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                this.ModelState.AddModelError(string.Empty, error.Description);
            }
        }

        private Task<ApplicationUser> GetCurrentUserAsync()
        {
            return this.userManager.GetUserAsync(this.HttpContext.User);
        }

        private IActionResult RedirectToLocal(string returnUrl)
        {
            // if (Url.IsLocalUrl(returnUrl))
            if (this.Request.IsLocal() && !string.IsNullOrEmpty(returnUrl))
            {
                return this.Redirect(returnUrl);
            }

            return this.RedirectToAction(nameof(HomeController.Index), "Home");
        }

        #endregion
    }

    internal static class HttpRequestExtensions
    {
        public static bool IsLocal(this HttpRequest req)
        {
            var connection = req.HttpContext.Connection;
            if (connection.RemoteIpAddress != null)
            {
                if (connection.LocalIpAddress != null)
                {
                    return connection.RemoteIpAddress.Equals(connection.LocalIpAddress);
                }

                return IPAddress.IsLoopback(connection.RemoteIpAddress);
            }

            // for in memory TestServer or when dealing with default connection info
            if ((connection.RemoteIpAddress == null) && (connection.LocalIpAddress == null))
            {
                return true;
            }

            return false;
        }
    }
}
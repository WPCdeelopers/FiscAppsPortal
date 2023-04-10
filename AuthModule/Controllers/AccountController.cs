using System;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using AuthModule.Models;
using AuthIntegration;
using System.Net.Mail;

namespace AuthModule.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        private ApplicationSignInManager _signInManager;
        private ApplicationUserManager _userManager;
        private IntegrationFunctionality IntegrateDll;
        private app_authentication_devEntities db = new app_authentication_devEntities();
        public AccountController()
        {
            IntegrateDll = new IntegrationFunctionality();
        }

        public AccountController(ApplicationUserManager userManager, ApplicationSignInManager signInManager)
        {
            UserManager = userManager;
            SignInManager = signInManager;
        }

        public ApplicationSignInManager SignInManager
        {
            get
            {
                return _signInManager ?? HttpContext.GetOwinContext().Get<ApplicationSignInManager>();
            }
            private set
            {
                _signInManager = value;
            }
        }

        public ApplicationUserManager UserManager
        {
            get
            {
                return _userManager ?? HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
            private set
            {
                _userManager = value;
            }
        }

        // The Authorize Action is the end point which gets called when you access any
        // protected Web API. If the user is not logged in then they will be redirected to 
        // the Login page. After a successful login you can call a Web API.
        [HttpGet]
        public ActionResult Authorize()
        {
            var claims = new ClaimsPrincipal(User).Claims.ToArray();
            var identity = new ClaimsIdentity(claims, "Bearer");
            AuthenticationManager.SignIn(identity);
            return new EmptyResult();
        }

        //
        // GET: /Account/Login
        [AllowAnonymous]
        //[Authorize]
        public ActionResult Login(string returnUrl,string message)
        {
            ViewData["Message"] = message;
            if (Request.IsAuthenticated)
            {
                string url = Request.Url.AbsolutePath;
                return RedirectToAction("Index", "Home");
            }
            else
            {
                // ViewBag.ReturnUrl = returnUrl;
                ViewBag.ReturnUrl = "/";
                return View();
            }
        }

        //
        // POST: /Account/Login
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Login(LoginViewModel model, string returnUrl)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            //string code = "code000789678543";
            //var callbackUrl = Url.Action("ConfirmEmail", "Account", new { userId = "b40c01e6-1e67-43e6-a73c-3100855c5b56", code = code }, protocol: Request.Url.Scheme);
            //await UserManager.SendEmailAsync("b40c01e6-1e67-43e6-a73c-3100855c5b56", "Confirm your account", "Please confirm your account by clicking <a href=\"" + callbackUrl + "\">here</a>");
            //string res = "1";
            //try
            //{
            //    MailMessage objeto_mail = new MailMessage();
            //    SmtpClient client = new SmtpClient();
            //    client.Port = 25;
            //    //client.Host = "wpcazvmexch2016.wpc.com";
            //    client.Host = "wpc-com.mail.protection.outlook.com";
            //    client.Timeout = 10000;
            //    client.DeliveryMethod = SmtpDeliveryMethod.Network;
            //    client.UseDefaultCredentials = false;
            //    //client.Credentials = new System.Net.NetworkCredential("Ravi.ks", "R@v1789ijn");
            //    //objeto_mail.From = new MailAddress("Ravi.ks@wpc.com");
            //    client.Credentials = new System.Net.NetworkCredential("muhasin.pk", "Ronaldo@CR8");
            //    objeto_mail.From = new MailAddress("muhasin.pk@wpc.com");
            //    objeto_mail.To.Add(new MailAddress("ravisa2@gmail.com"));
            //    objeto_mail.Subject = "Test";
            //    objeto_mail.IsBodyHtml = true;
            //    objeto_mail.Body = callbackUrl;
            //    client.Send(objeto_mail);

            //}
            //catch (Exception e)
            //{
            //    res = e.Message.ToString();
            //}

            //Check Email Verification
            var UserDetail = db.AspNetUsers.Where(s => s.Email == model.Email).FirstOrDefault();
            if (UserDetail != null)
            {
                if (UserDetail.EmailConfirmed == false)
                {
                    ModelState.AddModelError("", "Email verification pending!!");
                    return View(model);
                }
                else if (UserDetail.LockoutEnabled == false)
                {
                    return View("Lockout");
                }
                else { 
                // This doesn't count login failures towards account lockout
                // To enable password failures to trigger account lockout, change to shouldLockout: true
                var result = await SignInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, shouldLockout: false);
                switch (result)
                {
                    case SignInStatus.Success:
                        return RedirectToLocal(returnUrl);
                    case SignInStatus.LockedOut:
                        return View("Lockout");
                    case SignInStatus.RequiresVerification:
                        return RedirectToAction("SendCode", new { ReturnUrl = returnUrl, RememberMe = model.RememberMe });
                    case SignInStatus.Failure:
                    default:
                        ModelState.AddModelError("", "Invalid login attempt.");
                        return View(model);
                }
              }
            }
            else
            {
                ModelState.AddModelError("", "Account does not exists!!");
                return View(model);
            }
        }

        //[Route("/api/VerifyLogin")]
        //
        // GET: /Account/VerifyCode
        [AllowAnonymous]
        public async Task<ActionResult> VerifyCode(string provider, string returnUrl, bool rememberMe)
        {
            // Require that the user has already logged in via username/password or external login
            if (!await SignInManager.HasBeenVerifiedAsync())
            {
                return View("Error");
            }
            return View(new VerifyCodeViewModel { Provider = provider, ReturnUrl = returnUrl, RememberMe = rememberMe });
        }

        //
        // POST: /Account/VerifyCode
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> VerifyCode(VerifyCodeViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // The following code protects for brute force attacks against the two factor codes. 
            // If a user enters incorrect codes for a specified amount of time then the user account 
            // will be locked out for a specified amount of time. 
            // You can configure the account lockout settings in IdentityConfig
            var result = await SignInManager.TwoFactorSignInAsync(model.Provider, model.Code, isPersistent: model.RememberMe, rememberBrowser: model.RememberBrowser);
            switch (result)
            {
                case SignInStatus.Success:
                    return RedirectToLocal(model.ReturnUrl);
                case SignInStatus.LockedOut:
                    return View("Lockout");
                case SignInStatus.Failure:
                default:
                    ModelState.AddModelError("", "Invalid code.");
                    return View(model);
            }
        }

        //
        // GET: /Account/Register
        [AllowAnonymous]
        public ActionResult Register()
        {
            return View();
        }

        //
        // POST: /Account/Register
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Register(RegisterViewModel model)
        {

            if (ModelState.IsValid)
            {
                var user = new ApplicationUser { UserName = model.Email, Email = model.Email, Hometown = model.Hometown };
                var result = await UserManager.CreateAsync(user, model.Password);
                if (result.Succeeded)
                {

                    //await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);

                    // For more information on how to enable account confirmation and password reset please visit https://go.microsoft.com/fwlink/?LinkID=320771
                    // Send an email with this link
                    string code = await UserManager.GenerateEmailConfirmationTokenAsync(user.Id);
                    var callbackUrl = Url.Action("ConfirmEmail", "Account", new { userId = user.Id, code = code }, protocol: Request.Url.Scheme);
                    await UserManager.SendEmailAsync(user.Id, "Confirm your account", "Please confirm your account by clicking <a href=\"" + callbackUrl + "\">here</a>");

                    //return RedirectToAction("Index", "Home");



                    var ExistUserValidation = db.AppUserValidations.Where(s => s.UserId == user.Id).FirstOrDefault();
                    if (ExistUserValidation == null)
                    {
                        var applist = db.AppRegistrations.Select(s => new
                        {
                            Appid = s.Id,
                            Name = s.AppName,
                            DefaultAuth = s.DefaultAuthorized
                        }).ToList();

                        foreach (var item in applist)
                        {
                            AppUserValidation newAppUser = new AppUserValidation();
                            newAppUser.UserId = user.Id;
                            newAppUser.AppId = item.Appid;
                            newAppUser.IsGlobalAdmin = 0;
                            newAppUser.IsAppAdmin = 0;

                            if (item.DefaultAuth == 1)
                                newAppUser.IsAllowAccess = 1;
                            else
                                newAppUser.IsAllowAccess = 0;

                            db.AppUserValidations.Add(newAppUser);
                            db.SaveChanges();
                        }
                    }

                    //ModelState.AddModelError("Message", "A varification Link has been send to your registered email");
                    //return View(model);
                    string message = "Account confirmation mail has been sent, please verify before login !!";
                    return RedirectToAction("Login", "Account", new { message = message });

                }
                AddErrors(result);

            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }


        public async Task<String> RegisterByAdmin(ApplicationUser user,string password)
        {
            string msg = "";
            var result = await UserManager.CreateAsync(user, password);
            if (result.Succeeded)
            {

                //await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);

                // For more information on how to enable account confirmation and password reset please visit https://go.microsoft.com/fwlink/?LinkID=320771
                // Send an email with this link
                string code = await UserManager.GenerateEmailConfirmationTokenAsync(user.Id);
                var callbackUrl = Url.Action("ConfirmEmail", "Account", new { userId = user.Id, code = code }, protocol: Request.Url.Scheme);
                await UserManager.SendEmailAsync(user.Id, "Confirm your account", "Please confirm your account by clicking <a href=\"" + callbackUrl + "\">here</a>");

                //return RedirectToAction("Index", "Home");



                var ExistUserValidation = db.AppUserValidations.Where(s => s.UserId == user.Id).FirstOrDefault();
                if (ExistUserValidation == null)
                {
                    var applist = db.AppRegistrations.Select(s => new
                    {
                        Appid = s.Id,
                        Name = s.AppName,
                        DefaultAuth = s.DefaultAuthorized
                    }).ToList();

                    foreach (var item in applist)
                    {
                        AppUserValidation newAppUser = new AppUserValidation();
                        newAppUser.UserId = user.Id;
                        newAppUser.AppId = item.Appid;
                        newAppUser.IsGlobalAdmin = 0;
                        newAppUser.IsAppAdmin = 0;

                        if (item.DefaultAuth == 1)
                            newAppUser.IsAllowAccess = 1;
                        else
                            newAppUser.IsAllowAccess = 0;

                        db.AppUserValidations.Add(newAppUser);
                        db.SaveChanges();
                    }
                }       
                
                   msg= "string message = Account confirmation mail has been sent, please verify before login !!";
                return msg;

            }
            else
            {
                msg = result.Errors.FirstOrDefault();
                return msg;
            }
        }



        //
        // GET: /Account/ConfirmEmail
        [AllowAnonymous]
        public async Task<ActionResult> ConfirmEmail(string userId, string code)
        {
            if (userId == null || code == null)
            {
                return View("Error");
            }
            var result = await UserManager.ConfirmEmailAsync(userId, code);
            //if(result.Succeeded)
            //{

            //}
            return View(result.Succeeded ? "ConfirmEmail" : "Error");
        }

        //
        // GET: /Account/ForgotPassword
        [AllowAnonymous]
        public ActionResult ForgotPassword()
        {
            return View();
        }

        //
        // POST: /Account/ForgotPassword
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await UserManager.FindByNameAsync(model.Email);
               
               
                if (user == null || !(await UserManager.IsEmailConfirmedAsync(user.Id)))
                {
                    // Don't reveal that the user does not exist or is not confirmed
                    ViewBag.Msg = "User does not Exist OR Email Verification Pending";
                    return View("ForgotPasswordConfirmation");
                }

                var userPasswordNull = db.AspNetUsers.Where(s => s.Id == user.Id).FirstOrDefault();
                if(userPasswordNull!=null && userPasswordNull.PasswordHash==null)
                {
                    ViewBag.Msg = "Can not reset password for external login user.";
                    return View("ForgotPasswordConfirmation");
                }

                // For more information on how to enable account confirmation and password reset please visit https://go.microsoft.com/fwlink/?LinkID=320771
                // Send an email with this link
                string code = await UserManager.GeneratePasswordResetTokenAsync(user.Id);
                var callbackUrl = Url.Action("ResetPassword", "Account", new { userId = user.Id, code = code }, protocol: Request.Url.Scheme);
                await UserManager.SendEmailAsync(user.Id, "Reset Password", "Please reset your password by clicking <a href=\"" + callbackUrl + "\">here</a>");
                return RedirectToAction("ForgotPasswordConfirmation", "Account");
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        

        //
        // GET: /Account/ForgotPasswordConfirmation
        [AllowAnonymous]
        public ActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

        //
        // GET: /Account/ResetPassword
        [AllowAnonymous]
        public ActionResult ResetPassword(string code)
        {
            return code == null ? View("Error") : View();
        }

        //
        // POST: /Account/ResetPassword
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var user = await UserManager.FindByNameAsync(model.Email);
            if (user == null)
            {
                // Don't reveal that the user does not exist
                return RedirectToAction("ResetPasswordConfirmation", "Account");
            }
            var result = await UserManager.ResetPasswordAsync(user.Id, model.Code, model.Password);
            if (result.Succeeded)
            {
                return RedirectToAction("ResetPasswordConfirmation", "Account");
            }
            AddErrors(result);
            return View();
        }

        //
        // GET: /Account/ResetPasswordConfirmation
        [AllowAnonymous]
        public ActionResult ResetPasswordConfirmation()
        {
            return View();
        }

        //
        // POST: /Account/ExternalLogin
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult ExternalLogin(string provider, string returnUrl)
        {
            // Request a redirect to the external login provider
            return new ChallengeResult(provider, Url.Action("ExternalLoginCallback", "Account", new { ReturnUrl = returnUrl }));
        }

        //
        // GET: /Account/SendCode
        [AllowAnonymous]
        public async Task<ActionResult> SendCode(string returnUrl, bool rememberMe)
        {
            var userId = await SignInManager.GetVerifiedUserIdAsync();
            if (userId == null)
            {
                return View("Error");
            }
            var userFactors = await UserManager.GetValidTwoFactorProvidersAsync(userId);
            var factorOptions = userFactors.Select(purpose => new SelectListItem { Text = purpose, Value = purpose }).ToList();
            return View(new SendCodeViewModel { Providers = factorOptions, ReturnUrl = returnUrl, RememberMe = rememberMe });
        }

        //
        // POST: /Account/SendCode
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> SendCode(SendCodeViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View();
            }

            // Generate the token and send it
            if (!await SignInManager.SendTwoFactorCodeAsync(model.SelectedProvider))
            {
                return View("Error");
            }
            return RedirectToAction("VerifyCode", new { Provider = model.SelectedProvider, ReturnUrl = model.ReturnUrl, RememberMe = model.RememberMe });
        }

        //
        // GET: /Account/ExternalLoginCallback
        [AllowAnonymous]
        public async Task<ActionResult> ExternalLoginCallback(string returnUrl)
        {
            var loginInfo = await AuthenticationManager.GetExternalLoginInfoAsync();
            if (loginInfo == null)
            {
                return RedirectToAction("Login");
            }

            loginInfo.Email = loginInfo.DefaultUserName;
            // Sign in the user with this external login provider if the user already has a login
            var result = await SignInManager.ExternalSignInAsync(loginInfo, isPersistent: false);
            switch (result)
            {
                case SignInStatus.Success:
                    
                    return RedirectToAction("Index", "Home");
                    //return RedirectToLocal(returnUrl);
                case SignInStatus.LockedOut:
                    return View("Lockout");
                case SignInStatus.RequiresVerification:
                    return RedirectToAction("SendCode", new { ReturnUrl = returnUrl, RememberMe = false });
                case SignInStatus.Failure:
                default:
                    // If the user does not have an account, then prompt the user to create an account
                    ViewBag.ReturnUrl = returnUrl;
                    ViewBag.LoginProvider = loginInfo.Login.LoginProvider;
                    return View("ExternalLoginConfirmation", new ExternalLoginConfirmationViewModel { Email = loginInfo.Email });
            }
        }

        //
        // POST: /Account/ExternalLoginConfirmation
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ExternalLoginConfirmation(ExternalLoginConfirmationViewModel model, string returnUrl)
        {
            if (User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Index", "Manage");
            }

            if (ModelState.IsValid)
            {
                // Get the information about the user from the external login provider
                var info = await AuthenticationManager.GetExternalLoginInfoAsync();
                if (info == null)
                {
                    return View("ExternalLoginFailure");
                }
                var user = new ApplicationUser { UserName = model.Email, Email = model.Email, Hometown = model.Hometown };
                var result = await UserManager.CreateAsync(user);
                if (result.Succeeded)
                {
                    result = await UserManager.AddLoginAsync(user.Id, info.Login);
                    if (result.Succeeded)
                    {
                        await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
                        var ExistUserValidation = db.AppUserValidations.Where(s => s.UserId == user.Id).FirstOrDefault();
                        if (ExistUserValidation == null)
                        {
                            var applist = db.AppRegistrations.Select(s => new
                            {
                                Appid = s.Id,
                                Name = s.AppName,
                                DefaultAuth = s.DefaultAuthorized
                            }).ToList();

                            foreach (var item in applist)
                            {
                                AppUserValidation newAppUser = new AppUserValidation();
                                newAppUser.UserId = user.Id;
                                newAppUser.AppId = item.Appid;
                                newAppUser.IsGlobalAdmin = 0;
                                newAppUser.IsAppAdmin = 0;

                                if (item.DefaultAuth == 1)
                                    newAppUser.IsAllowAccess = 1;
                                else
                                    newAppUser.IsAllowAccess = 0;

                                db.AppUserValidations.Add(newAppUser);
                                db.SaveChanges();
                            }
                        }
                        return RedirectToLocal(returnUrl);
                    }
                }
                AddErrors(result);
            }

            ViewBag.ReturnUrl = returnUrl;
            return View(model);
        }

        //
        // POST: /Account/LogOff
        //[HttpPost]
        //[ValidateAntiForgeryToken]
        public ActionResult LogOff()
        {
            try
            {
               
                AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
                if (Session["token"] != null)
                {
                    string token = Session["token"].ToString();
                    var logoff = IntegrateDll.LogOff(token, "");
                    Session["token"] = null;
                    Session.Remove("token");
                    Session.Abandon();
                }
                
                return RedirectToAction("login", "Account");

            }
            catch(Exception e)
            {
                return RedirectToAction("login", "Account");
            }
        }

        //
        // GET: /Account/ExternalLoginFailure
        [AllowAnonymous]
        public ActionResult ExternalLoginFailure()
        {
            return View();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (_userManager != null)
                {
                    _userManager.Dispose();
                    _userManager = null;
                }

                if (_signInManager != null)
                {
                    _signInManager.Dispose();
                    _signInManager = null;
                }
            }

            base.Dispose(disposing);
        }

        #region Dll Integrate



        //[HttpGet]
        //public void setLogin(string userid, string Email)   //string token,
        //{

        //    //Session["token"] = token;
        //    //var user = UserManager.FindById(User.Identity.GetUserId());          
        //    //int res= IntegrateDll.Login(token, user.Id, "", user.Email);
        //    //return RedirectToLocal("/");

        //    string token = Guid.NewGuid().ToString();
        //    Session["token"] = token;
        //    int res = IntegrateDll.Login(token, userid, "", Email);

        //}

        #endregion

        #region Api For Mobile
        [AllowAnonymous]
       public async Task<string> VerifyLogin(string AppKey, string Email, string Password)
        {
            try
            {
                if (!string.IsNullOrEmpty(AppKey) && !string.IsNullOrEmpty(Email) && !string.IsNullOrEmpty(Password))
                {
                    var App = db.AppRegistrations.Where(a => a.Url == AppKey && a.AppType == 2).FirstOrDefault();
                    if (App != null)
                    {
                        //Check Email Verification
                        var UserDetail = db.AspNetUsers.Where(s => s.Email == Email).FirstOrDefault();
                        if (UserDetail != null)
                        {
                            if (UserDetail.EmailConfirmed == false)
                            {
                                return LoginResponce.User_VarificationPending.ToString("d");  //User VarificationPending;
                            }
                            else
                            {
                                // This doesn't count login failures towards account lockout
                                // To enable password failures to trigger account lockout, change to shouldLockout: true
                                var result = await SignInManager.PasswordSignInAsync(Email, Password, false, shouldLockout: false);

                                switch (result)
                                {
                                    case SignInStatus.Success:
                                        //var userid = db.AspNetUsers.Where(s => s.Email == Email).Select(t => t.Id).FirstOrDefault();
                                        //string token = Guid.NewGuid().ToString();
                                        //int res = IntegrateDll.Login(token, userid, App.Id, Email);
                                        return LoginResponce.Login_Successfull.ToString("d"); ;  //Login successfull;
                                    case SignInStatus.LockedOut:
                                        return LoginResponce.Account_Lock.ToString("d");    //Account Lock                   
                                    case SignInStatus.Failure:
                                    default:
                                        return LoginResponce.Invalid_UserName_Password.ToString("d");    //Invalid UserName ,Password;
                                }
                            }
                        }
                        else
                        {
                            return DeviceRegisterResponce.Invalid_User.ToString("d");  //User Not Exists;
                        }
                    }
                    else
                    {
                        return LoginResponce.Wrong_AppKey_OR_App_not_registered.ToString("d");  //Wrong AppKey OR App not registered.
                    }
                }
                else
                {
                    return LoginResponce.Bad_Request_with_Parameter_Missing.ToString("d");  //Bad Request With Parameter Missing;
                }

            }
            catch (Exception ex)
            {
                return LoginResponce.Try_Catch_ApiError.ToString("d");
            }
        }

        [AllowAnonymous]
        public string verifyRegisterDevice(string DeviceID, string AppKey, string Email)
        {
            string res = "";
            try
            {
                if (!string.IsNullOrEmpty(DeviceID) && !string.IsNullOrEmpty(AppKey) && !string.IsNullOrEmpty(Email))
                {
                    // Check Email/User Registration
                    var UserDetail = db.AspNetUsers.Where(s => s.Email == Email).FirstOrDefault();
                    if(UserDetail!=null)
                    {
                        if (UserDetail.EmailConfirmed == false)
                        {
                            res= LoginResponce.User_VarificationPending.ToString("d");
                        }
                        else
                        {
                            //Getting App Detail
                            var App = db.AppRegistrations.Where(a => a.Url == AppKey).FirstOrDefault();
                            if (App != null)
                            {
                               var Device= db.UserDeviceRegistrations.Where(d => d.UserID == UserDetail.Id && d.DeviceID == DeviceID && d.AppID == App.Id && d.IsDeleted==false).FirstOrDefault();
                                if(Device!=null)
                                {
                                    if (Device.DeviceConfirmed == true)
                                    {
                                        string token = Guid.NewGuid().ToString();
                                        int resLogin = IntegrateDll.Login(token, UserDetail.Id, App.Id, Email,DeviceID);
                                        res = "Token-"+token;
                                    }
                                    else
                                    {
                                        res = DeviceRegisterResponce.Device_Registration_Verification_Pending.ToString("d");
                                    }
                                }
                                else
                                {
                                    res = DeviceRegisterResponce.Device_Not_Register.ToString("d");
                                }
                            }
                            else
                            {
                                res = LoginResponce.Wrong_AppKey_OR_App_not_registered.ToString("d");
                            }
                        }
                    }
                    else
                    {
                        res=DeviceRegisterResponce.Invalid_User.ToString("d");
                    }
                }
                else
                {
                    res = LoginResponce.Bad_Request_with_Parameter_Missing.ToString("d");
                }
            }catch(Exception e)
            {
                res = LoginResponce.Try_Catch_ApiError.ToString("d");
            }

            return res;
        }

        [AllowAnonymous]
        public async Task<string> registerDevice(string DeviceID, string AppKey, string Email,string DeviceName,string Os,string OsVersion)
        {
            string res = "";
            try
            {
                if (!string.IsNullOrEmpty(DeviceID) && !string.IsNullOrEmpty(AppKey) && !string.IsNullOrEmpty(Email)&& !string.IsNullOrEmpty(DeviceName) && !string.IsNullOrEmpty(Os) && !string.IsNullOrEmpty(OsVersion))
                {
                    // Check Email/User Registration
                    var UserDetail = db.AspNetUsers.Where(s => s.Email == Email).FirstOrDefault();
                    if (UserDetail != null)
                    {
                        if (UserDetail.EmailConfirmed == false)
                        {
                            res = LoginResponce.User_VarificationPending.ToString("d");
                        }
                        else
                        {
                            //Getting App Detail
                            var App = db.AppRegistrations.Where(a => a.Url == AppKey).FirstOrDefault();
                            if (App != null)
                            {
                                var Device = db.UserDeviceRegistrations.Where(d => d.UserID == UserDetail.Id && d.DeviceID == DeviceID && d.AppID == App.Id).FirstOrDefault();
                                if (Device == null)
                                {
                                    UserDeviceRegistration UDR = new UserDeviceRegistration();
                                    UDR.UserID = UserDetail.Id;
                                    UDR.AppID = App.Id;
                                    UDR.DeviceID = DeviceID;
                                    UDR.Email = Email;
                                    UDR.DeviceName = DeviceName;
                                    UDR.DeviceOs = Os;
                                    UDR.DeviceOsVersion = OsVersion;
                                    UDR.DeviceConfirmed = false;
                                    UDR.IsActive = true;
                                    UDR.IsDeleted = false;
                                    db.UserDeviceRegistrations.Add(UDR);
                                    db.SaveChanges();

                                    var callbackUrl = Url.Action("ConfirmDeviceRegistration", "Account", new { userId = UserDetail.Id, DeviceID = DeviceID,AppId=App.Id.ToString() }, protocol: Request.Url.Scheme);
                                    await UserManager.SendEmailAsync(UserDetail.Id, "Confirm your Device Registration", "Please confirm your Device Registration by clicking <a href=\"" + callbackUrl + "\">here</a>");

                                    res = DeviceRegisterResponce.Device_Registration_Verification_Mailsend.ToString("d");
                                }
                                else
                                {
                                    res = DeviceRegisterResponce.Device_Already_Register.ToString("d");
                                }
                            }
                            else
                            {
                                res = LoginResponce.Wrong_AppKey_OR_App_not_registered.ToString("d");
                            }
                        }
                    }
                    else
                    {
                        res = DeviceRegisterResponce.Invalid_User.ToString("d");
                    }
                }
                else
                {
                    res = LoginResponce.Bad_Request_with_Parameter_Missing.ToString("d");
                }
            }
            catch (Exception e)
            {
                res = LoginResponce.Try_Catch_ApiError.ToString("d");
            }

            return res;
        }

        [AllowAnonymous]
        public ActionResult ConfirmDeviceRegistration(string userId, string DeviceID,string AppId)
        {
            string res = "";
            try
            {
                if (!string.IsNullOrEmpty(userId) && !string.IsNullOrEmpty(DeviceID) && !string.IsNullOrEmpty(AppId))
                {
                    int appid = Convert.ToInt32(AppId);
                    var Device = db.UserDeviceRegistrations.Where(d => d.UserID == userId && d.DeviceID == DeviceID && d.AppID == appid).FirstOrDefault();
                    Device.DeviceConfirmed = true;
                    db.SaveChanges();
                    res = "Thank you for confirming Device Registration.";
                }
                else
                {
                    res = "Error-Value Missing !!";
                }
            }catch(Exception e)
            {
                res = "Error in Verification !!";
            }
            ViewBag.Msg = res;
                
            return View();
        }

      
        [AllowAnonymous]      
        public async Task<string> resetApiUserPassword(string AppKey,string Email)
        {
            string result = "";
            try
            {

                if (!string.IsNullOrEmpty(AppKey) && !string.IsNullOrEmpty(Email))
                {
                    var App = db.AppRegistrations.Where(a => a.Url == AppKey).FirstOrDefault();
                    if (App != null)
                    {
                        var user = await UserManager.FindByNameAsync(Email);
                       
                        if (user == null || !(await UserManager.IsEmailConfirmedAsync(user.Id)))
                        {
                            // Don't reveal that the user does not exist or is not confirmed
                            result = DeviceRegisterResponce.Invalid_User.ToString("d");
                        }
                        else
                        {
                            var userPasswordNull = db.AspNetUsers.Where(s => s.Id == user.Id).FirstOrDefault();
                            if (userPasswordNull != null && userPasswordNull.PasswordHash == null)
                            {
                                result = LoginResponce.External_User_Password_Not_Reset.ToString("d");
                            }
                            else
                            {
                                // For more information on how to enable account confirmation and password reset please visit https://go.microsoft.com/fwlink/?LinkID=320771
                                // Send an email with this link
                                string code = await UserManager.GeneratePasswordResetTokenAsync(user.Id);
                                var callbackUrl = Url.Action("ResetPassword", "Account", new { userId = user.Id, code = code }, protocol: Request.Url.Scheme);
                                await UserManager.SendEmailAsync(user.Id, "Reset Password", "Please reset your password by clicking <a href=\"" + callbackUrl + "\">here</a>");
                                result = LoginResponce.Reset_Password_Link_Mailsend.ToString("d");
                            }
                        }
                        
                    }
                    else
                    {
                        result=LoginResponce.Wrong_AppKey_OR_App_not_registered.ToString("d");
                    }
                     
                }
            }catch(Exception e)
            {
                result = LoginResponce.Try_Catch_ApiError.ToString("d");
            }

            // If we got this far, something failed, redisplay form
            return result;
        }

        #endregion

        #region Helpers
        // Used for XSRF protection when adding external logins
        private const string XsrfKey = "XsrfId";

        private IAuthenticationManager AuthenticationManager
        {
            get
            {
                return HttpContext.GetOwinContext().Authentication;
            }
        }

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error);
            }
        }

        private ActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return RedirectToAction("Index", "Home");
        }

        internal class ChallengeResult : HttpUnauthorizedResult
        {
            public ChallengeResult(string provider, string redirectUri)
                : this(provider, redirectUri, null)
            {
            }

            public ChallengeResult(string provider, string redirectUri, string userId)
            {
                LoginProvider = provider;
                RedirectUri = redirectUri;
                UserId = userId;
            }

            public string LoginProvider { get; set; }
            public string RedirectUri { get; set; }
            public string UserId { get; set; }

            public override void ExecuteResult(ControllerContext context)
            {
                var properties = new AuthenticationProperties { RedirectUri = RedirectUri };
                if (UserId != null)
                {
                    properties.Dictionary[XsrfKey] = UserId;
                }
                context.HttpContext.GetOwinContext().Authentication.Challenge(properties, LoginProvider);
            }
        }
        #endregion
    }
}

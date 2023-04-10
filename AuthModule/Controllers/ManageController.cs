using System;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using AuthModule.Models;
using PagedList;

namespace AuthModule.Controllers
{
    [Authorize]
    public class ManageController : Controller
    {
        private ApplicationSignInManager _signInManager;
        private ApplicationUserManager _userManager;
        private app_authentication_devEntities db = new app_authentication_devEntities();

        public ManageController()
        {
        }

        public ManageController(ApplicationUserManager userManager, ApplicationSignInManager signInManager)
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

        //
        // GET: /Manage/Index
        public async Task<ActionResult> Index(ManageMessageId? message)
        {
            ViewBag.StatusMessage =
                message == ManageMessageId.ChangePasswordSuccess ? "Your password has been changed."
                : message == ManageMessageId.SetPasswordSuccess ? "Your password has been set."
                : message == ManageMessageId.SetTwoFactorSuccess ? "Your two-factor authentication provider has been set."
                : message == ManageMessageId.Error ? "An error has occurred."
                : message == ManageMessageId.AddPhoneSuccess ? "Your phone number was added."
                : message == ManageMessageId.RemovePhoneSuccess ? "Your phone number was removed."
                : "";

            var userId = User.Identity.GetUserId();
            var model = new IndexViewModel
            {
                HasPassword = HasPassword(),
                PhoneNumber = await UserManager.GetPhoneNumberAsync(userId),
                TwoFactor = await UserManager.GetTwoFactorEnabledAsync(userId),
                Logins = await UserManager.GetLoginsAsync(userId),
                BrowserRemembered = await AuthenticationManager.TwoFactorBrowserRememberedAsync(userId)
            };
            return View(model);
        }

        //
        // POST: /Manage/RemoveLogin
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> RemoveLogin(string loginProvider, string providerKey)
        {
            ManageMessageId? message;
            var result = await UserManager.RemoveLoginAsync(User.Identity.GetUserId(), new UserLoginInfo(loginProvider, providerKey));
            if (result.Succeeded)
            {
                var user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
                if (user != null)
                {
                    await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
                }
                message = ManageMessageId.RemoveLoginSuccess;
            }
            else
            {
                message = ManageMessageId.Error;
            }
            return RedirectToAction("ManageLogins", new { Message = message });
        }

        

        //
        // GET: /Manage/AddPhoneNumber
        public ActionResult AddPhoneNumber()
        {
            return View();
        }

        //
        // POST: /Manage/AddPhoneNumber
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> AddPhoneNumber(AddPhoneNumberViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            // Generate the token and send it
            var code = await UserManager.GenerateChangePhoneNumberTokenAsync(User.Identity.GetUserId(), model.Number);
            if (UserManager.SmsService != null)
            {
                var message = new IdentityMessage
                {
                    Destination = model.Number,
                    Body = "Your security code is: " + code
                };
                await UserManager.SmsService.SendAsync(message);
            }
            return RedirectToAction("VerifyPhoneNumber", new { PhoneNumber = model.Number });
        }

        //
        // POST: /Manage/EnableTwoFactorAuthentication
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> EnableTwoFactorAuthentication()
        {
            await UserManager.SetTwoFactorEnabledAsync(User.Identity.GetUserId(), true);
            var user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
            if (user != null)
            {
                await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
            }
            return RedirectToAction("Index", "Manage");
        }

        //
        // POST: /Manage/DisableTwoFactorAuthentication
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> DisableTwoFactorAuthentication()
        {
            await UserManager.SetTwoFactorEnabledAsync(User.Identity.GetUserId(), false);
            var user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
            if (user != null)
            {
                await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
            }
            return RedirectToAction("Index", "Manage");
        }

        //
        // GET: /Manage/VerifyPhoneNumber
        public async Task<ActionResult> VerifyPhoneNumber(string phoneNumber)
        {
            var code = await UserManager.GenerateChangePhoneNumberTokenAsync(User.Identity.GetUserId(), phoneNumber);
            // Send an SMS through the SMS provider to verify the phone number
            return phoneNumber == null ? View("Error") : View(new VerifyPhoneNumberViewModel { PhoneNumber = phoneNumber });
        }

        //
        // POST: /Manage/VerifyPhoneNumber
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> VerifyPhoneNumber(VerifyPhoneNumberViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var result = await UserManager.ChangePhoneNumberAsync(User.Identity.GetUserId(), model.PhoneNumber, model.Code);
            if (result.Succeeded)
            {
                var user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
                if (user != null)
                {
                    await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
                }
                return RedirectToAction("Index", new { Message = ManageMessageId.AddPhoneSuccess });
            }
            // If we got this far, something failed, redisplay form
            ModelState.AddModelError("", "Failed to verify phone");
            return View(model);
        }

        //
        // POST: /Manage/RemovePhoneNumber
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> RemovePhoneNumber()
        {
            var result = await UserManager.SetPhoneNumberAsync(User.Identity.GetUserId(), null);
            if (!result.Succeeded)
            {
                return RedirectToAction("Index", new { Message = ManageMessageId.Error });
            }
            var user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
            if (user != null)
            {
                await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
            }
            return RedirectToAction("Index", new { Message = ManageMessageId.RemovePhoneSuccess });
        }

        //
        // GET: /Manage/ChangePassword
        public ActionResult ChangePassword()
        {
            
            ViewBag.Role =getRole();
            string Userid =getUserId();
            int userType = 0; //LocalUser
            var userPasswordNull = db.AspNetUsers.Where(s => s.Id == Userid).FirstOrDefault();
            if (userPasswordNull != null && userPasswordNull.PasswordHash == null)
            {
                userType = 1; //External User
            }

            ViewBag.User = userType;
            return View();
        }

        //
        // POST: /Manage/ChangePassword
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ChangePassword(ChangePasswordViewModel model)
        {
            
            ViewBag.Role = getRole();
            string Userid = getUserId();
            int userType = 0; //LocalUser
            var userPasswordNull = db.AspNetUsers.Where(s => s.Id == Userid).FirstOrDefault();
            if (userPasswordNull != null && userPasswordNull.PasswordHash == null)
            {
                userType = 1; //External User
            }

            ViewBag.User = userType;





            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var result = await UserManager.ChangePasswordAsync(User.Identity.GetUserId(), model.OldPassword, model.NewPassword);
            if (result.Succeeded)
            {
                var user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
                if (user != null)
                {
                    await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
                }
                return RedirectToRoute("HomePage"); /*RedirectToAction("Index", new { Message = ManageMessageId.ChangePasswordSuccess })*/;
            }
            AddErrors(result);
            return View(model);
        }

        //
        // GET: /Manage/SetPassword
        public ActionResult SetPassword()
        {
            return View();
        }

        //
        // POST: /Manage/SetPassword
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> SetPassword(SetPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var result = await UserManager.AddPasswordAsync(User.Identity.GetUserId(), model.NewPassword);
                if (result.Succeeded)
                {
                    var user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
                    if (user != null)
                    {
                        await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
                    }
                    return RedirectToAction("Index", new { Message = ManageMessageId.SetPasswordSuccess });
                }
                AddErrors(result);
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        //
        // GET: /Manage/ManageLogins
        public async Task<ActionResult> ManageLogins(ManageMessageId? message)
        {
            ViewBag.StatusMessage =
                message == ManageMessageId.RemoveLoginSuccess ? "The external login was removed."
                : message == ManageMessageId.Error ? "An error has occurred."
                : "";
            var user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
            if (user == null)
            {
                return View("Error");
            }
            var userLogins = await UserManager.GetLoginsAsync(User.Identity.GetUserId());
            var otherLogins = AuthenticationManager.GetExternalAuthenticationTypes().Where(auth => userLogins.All(ul => auth.AuthenticationType != ul.LoginProvider)).ToList();
            ViewBag.ShowRemoveButton = user.PasswordHash != null || userLogins.Count > 1;
            return View(new ManageLoginsViewModel
            {
                CurrentLogins = userLogins,
                OtherLogins = otherLogins
            });
        }

        //
        // POST: /Manage/LinkLogin
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LinkLogin(string provider)
        {
            // Request a redirect to the external login provider to link a login for the current user
            return new AccountController.ChallengeResult(provider, Url.Action("LinkLoginCallback", "Manage"), User.Identity.GetUserId());
        }

        //
        // GET: /Manage/LinkLoginCallback
        public async Task<ActionResult> LinkLoginCallback()
        {
            var loginInfo = await AuthenticationManager.GetExternalLoginInfoAsync(XsrfKey, User.Identity.GetUserId());
            if (loginInfo == null)
            {
                return RedirectToAction("ManageLogins", new { Message = ManageMessageId.Error });
            }
            var result = await UserManager.AddLoginAsync(User.Identity.GetUserId(), loginInfo.Login);
            return result.Succeeded ? RedirectToAction("ManageLogins") : RedirectToAction("ManageLogins", new { Message = ManageMessageId.Error });
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && _userManager != null)
            {
                _userManager.Dispose();
                _userManager = null;
            }

            base.Dispose(disposing);
        }

        #region UserManagement
        public ActionResult UserManagement(string searchtxt, int? page)
        {
            //var AppTypelist = db.AppTypes.Select(s => new
            //{
            //    Id = s.Id,
            //    AppType = s.AppType1
            //}).ToList();
            //ViewBag.AppType = AppTypelist;

           Int16 pageSize = 8;
            int pageNumber = (page ?? 1);
            ViewBag.Role = getRole();
            ViewBag.searchtxt = searchtxt;
            if (string.IsNullOrEmpty(searchtxt))
            {
                var Userlist = db.AspNetUsers.Select(s => new AspUser
                {
                    UserId = s.Id,
                    Email = s.Email,
                    IsLock = s.LockoutEnabled,
                    Password = s.PasswordHash                 
                }).OrderBy(s => s.UserId);

                return View(Userlist.ToPagedList(pageNumber, pageSize));
            }
            else
            {
                var Userlist = db.AspNetUsers.Where(y => y.Email.Contains(searchtxt)).Select(s => new AspUser
                {
                    UserId = s.Id,
                    Email = s.Email,
                    IsLock = s.LockoutEnabled,
                    Password = s.PasswordHash                   
                }).OrderBy(s => s.UserId);
                return View(Userlist.ToPagedList(pageNumber, pageSize));
            }

            // return View();
        }

        public ActionResult enableDesableUser(string Id, bool? Isactive)
        {
            var user = db.AspNetUsers.Where(s => s.Id == Id).FirstOrDefault();
            if (user != null)
            {
                user.LockoutEnabled = (bool)Isactive;
                db.SaveChanges();
            }
            return RedirectToAction("UserManagement");
        }

        public ActionResult DeleteUser(string Id)
        {
            //var user = db.AspNetUsers.Where(s => s.Id == Id).FirstOrDefault();
            var user = UserManager.FindById(Id);
            if (user != null)
            {
                int role = getRoleByEmail(user.Email);
                if (role != 0)
                {
                    UserManager.Delete(user);
                    var userDeviceList = db.UserDeviceRegistrations.Where(s => s.UserID == Id).ToList();
                    foreach (UserDeviceRegistration u in userDeviceList)
                    {
                        u.IsDeleted = true;
                    }

                    var AppUserList = db.AppUserValidations.Where(t => t.UserId == Id).ToList();
                    foreach (AppUserValidation a in AppUserList)
                    {
                        a.IsDeleted = 1;

                    }
                    db.SaveChanges();
                    return RedirectToAction("UserManagement");
                }
                else
                {
                    ViewBag.Error = "Can not Delete GlobalAdmin-" + user.Email;
                    return View("UserManagement");
                }
            }
            return RedirectToAction("UserManagement");

        }

        [HttpPost]
        public async Task<string> adminResetPassword(string UserId)
        {
            string Msg = "";
            var user = db.AspNetUsers.Where(s => s.Id == UserId).FirstOrDefault();
            //var userEmail = await UserManager.FindByNameAsync(user.Email);


            if (user == null || !(await UserManager.IsEmailConfirmedAsync(UserId)))
            {
                // Don't reveal that the user does not exist or is not confirmed
                Msg = "User does not Exist OR Email Verification Pending";

            }


            if (user != null && user.PasswordHash == null)
            {
                Msg = "Can not reset password for external login user.";

            }

            // For more information on how to enable account confirmation and password reset please visit https://go.microsoft.com/fwlink/?LinkID=320771
            // Send an email with this link
            string code = await UserManager.GeneratePasswordResetTokenAsync(user.Id);
            var callbackUrl = Url.Action("ResetPassword", "Account", new { userId = user.Id, code = code }, protocol: Request.Url.Scheme);
            await UserManager.SendEmailAsync(user.Id, "Reset Password", "Please reset your password by clicking <a href=\"" + callbackUrl + "\">here</a>");
            Msg = "Reser Password Link mail Succesfully!!";


            // If we got this far, something failed, redisplay form
            return Msg;
        }


        public ActionResult UserByApp(int id, int? page)
        {
            //var userlist = (from user in db.AspNetUsers
            //                join userValid in db.AppUserValidations on user.Id equals userValid.UserId into userinfo
            //                from userValids in userinfo.DefaultIfEmpty()
            //                select new UserValidationViewModel
            //                {
            //                    UserId = user.Id,
            //                    Email = user.Email,
            //                    AppId = userValids.AppId,
            //                    IsGlobalAdmin = userValids.IsGlobalAdmin == null || userValids.IsGlobalAdmin == 0 ? false : true,
            //                    IsAppAdmin = userValids.IsAppAdmin == null || userValids.IsAppAdmin == 0 ? false : true,
            //                    IsAllowAccess = userValids.IsAllowAccess == null || userValids.IsAllowAccess == 0 ? false : true
            //                }).ToList();

            int pageSize = 8;
            int pageNumber = (page ?? 1);

            ViewBag.Role = getRole();
            ViewBag.Id = id;

            var Userlist = db.AspNetUsers.Select(s => new
            {
                UserId = s.Id,
                Email = s.Email,
                AppId = db.AppUserValidations.Where(t => t.UserId == s.Id && t.AppId == id).Select(x => x.AppId).FirstOrDefault(),
                IsGlobalAdmin = db.AppUserValidations.Where(t => t.UserId == s.Id && t.AppId == id).Select(x => x.IsGlobalAdmin).FirstOrDefault(),
                IsAppAdmin = db.AppUserValidations.Where(t => t.UserId == s.Id && t.AppId == id).Select(x => x.IsAppAdmin).FirstOrDefault(),
                IsAllowAccess = db.AppUserValidations.Where(t => t.UserId == s.Id && t.AppId == id).Select(x => x.IsAllowAccess).FirstOrDefault(),
            }).ToList();

            var userAppList = Userlist.Select(s => new UserValidationViewModel
            {
                UserId = s.UserId,
                Email = s.Email,
                AppId = s.AppId,
                IsGlobalAdmin = s.IsGlobalAdmin == null || s.IsGlobalAdmin == 0 ? false : true,
                IsAppAdmin = s.IsAppAdmin == null || s.IsAppAdmin == 0 ? false : true,
                IsAllowAccess = s.IsAllowAccess == null || s.IsAllowAccess == 0 ? false : true
            }).OrderBy(s => s.UserId);

            return PartialView("_UserValidationView", userAppList.ToPagedList(pageNumber, pageSize));
        }


        [HttpPost]
        public ActionResult GetAppByAppType(int AppTypeId)
        {
            int role = getRole();

            if (role == 0)
            {
                var list = db.AppRegistrations.Where(g => g.IsActive == 1 && g.AppType == AppTypeId).Select(s => new
                {
                    AppId = s.Id,
                    AppName = s.AppName
                }).ToList();

                return Json(list, JsonRequestBehavior.AllowGet);
            }
            else if (role == 1)
            {
                string userid = getUserId();
                var authAppId = db.AppUserValidations.Where(s => s.UserId == userid && s.IsAppAdmin == 1).Select(t => t.AppId).ToArray();
                var list = db.AppRegistrations.Where(x => authAppId.Contains(x.Id) && x.IsActive == 1 && x.AppType == AppTypeId).Select(s => new
                {
                    AppId = s.Id,
                    AppName = s.AppName
                }).ToList();

                return Json(list, JsonRequestBehavior.AllowGet);

            }
            else
            {
                string error = "-1";
                return Json(error, JsonRequestBehavior.AllowGet);
            }

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

        private bool HasPassword()
        {
            var user = UserManager.FindById(User.Identity.GetUserId());
            if (user != null)
            {
                return user.PasswordHash != null;
            }
            return false;
        }

        private bool HasPhoneNumber()
        {
            var user = UserManager.FindById(User.Identity.GetUserId());
            if (user != null)
            {
                return user.PhoneNumber != null;
            }
            return false;
        }


        public int getRole()
        {
            int role = -1;
            string Email = User.Identity.Name;
            var userid = db.AspNetUsers.Where(s => s.Email == Email).Select(t => t.Id).FirstOrDefault();
            var GlobalAdmin = db.AppUserValidations.Where(s => (s.UserId == userid) && (s.IsGlobalAdmin == 1)).FirstOrDefault();
            if (GlobalAdmin != null)
            {
                role = (int)Role.GlobalAdmin;

            }
            else
            {
                var AppAdmin = db.AppUserValidations.Where(s => s.UserId == userid && s.IsAppAdmin == 1).FirstOrDefault();
                if (AppAdmin != null)
                    role = (int)Role.AppAdmin;
                else
                    role = (int)Role.User;

            }

            return role;
        }

        public int getRoleByEmail(string Email)
        {
            int role = -1;
            //string Email = User.Identity.Name;
            var userid = db.AspNetUsers.Where(s => s.Email == Email).Select(t => t.Id).FirstOrDefault();
            var GlobalAdmin = db.AppUserValidations.Where(s => (s.UserId == userid) && (s.IsGlobalAdmin == 1)).FirstOrDefault();
            if (GlobalAdmin != null)
            {
                role = (int)Role.GlobalAdmin;

            }
            else
            {
                var AppAdmin = db.AppUserValidations.Where(s => s.UserId == userid && s.IsAppAdmin == 1).FirstOrDefault();
                if (AppAdmin != null)
                    role = (int)Role.AppAdmin;
                else
                    role = (int)Role.User;

            }

            return role;
        }
        public string getUserId()
        {
            string Email = User.Identity.Name;
            var userid = db.AspNetUsers.Where(s => s.Email == Email).Select(t => t.Id).FirstOrDefault();
            return userid;
        }


        public enum ManageMessageId
        {
            AddPhoneSuccess,
            ChangePasswordSuccess,
            SetTwoFactorSuccess,
            SetPasswordSuccess,
            RemoveLoginSuccess,
            RemovePhoneSuccess,
            Error
        }

        #endregion
    }
}
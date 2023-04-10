using System;
using System.Collections.Generic;
using System.Linq;
using System.Web.Mvc;
using AuthModule.Models;
using System.IO;
using AuthIntegration;
using PagedList;
using Microsoft.AspNet.Identity;
using System.Threading.Tasks;
using System.Web;
using Microsoft.AspNet.Identity.Owin;

namespace AuthModule.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
       private app_authentication_devEntities db = new app_authentication_devEntities();
       private IntegrationFunctionality IntegrateDll = new IntegrationFunctionality();

        private int pageSize = 8;

        public ActionResult Index()
        {
            //if (!Request.IsAuthenticated)
            //{
            
                ViewBag.Role = getRole();
                string CurrentUserid = getUserId();
            //var data = IntegrateDll.IsLogin("2115826f-b98b-40e6-8175-c63f9c8e7a15");

            //string Email = User.Identity.Name;
            //setLogin(CurrentUserid, Email);
            if (Session["token"] == null)
            {
                string token = Guid.NewGuid().ToString();
                Session["token"] = token;
            }

                var AdminUser = db.AppUserValidations.Where(s => s.UserId == CurrentUserid && s.IsGlobalAdmin == 1 && s.IsAllowAccess == 1).ToList();
                if (AdminUser != null)
                {
                var AppIdList = db.AppUserValidations.Where(s => s.UserId == CurrentUserid && s.IsAllowAccess==1).Select(t => t.AppId).ToArray();

                var Applist = db.AppRegistrations.Where(s => AppIdList.Contains(s.Id) && s.IsActive == 1 && s.AppType == 1).ToList();   //AppType==1 forAll Web App
                return View(Applist);
                }
                else
                {
                    var AppIdList = db.AppUserValidations.Where(s => s.UserId == CurrentUserid && s.IsAllowAccess == 1).Select(t => t.AppId).ToArray();
                    var Applist = db.AppRegistrations.Where(s => AppIdList.Contains(s.Id) && s.IsActive == 1 && s.AppType == 1).ToList(); //AppType==1 forAll Web App

                return View(Applist);
                }
                     
        }
     
        public void setLogin(string userid, string Email,int AppId)   //string token,
        {
            if (Session["token"] != null)
            {
                //string token = Guid.NewGuid().ToString();
                //Session["token"] = token;
                string token = Session["token"].ToString();
                int res = IntegrateDll.Login(token, userid, AppId, Email);
            }

        }

        public int getRole()
        {
            int role = -1;
            string Email = User.Identity.Name;
            var userid = db.AspNetUsers.Where(s => s.Email == Email).Select(t => t.Id).FirstOrDefault();
            var GlobalAdmin = db.AppUserValidations.Where(s => (s.UserId == userid) && (s.IsGlobalAdmin==1)).FirstOrDefault();
            if (GlobalAdmin != null)
            {
                role = (int)Role.GlobalAdmin;
                
            }
            else
            {
                var AppAdmin = db.AppUserValidations.Where(s => s.UserId == userid && s.IsAppAdmin == 1).FirstOrDefault();
                if(AppAdmin!=null)
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

        #region APP Management and Registration
        [HttpGet]
        public ActionResult AppRegistration()
        {
            AppRegistrationModel newApp = new AppRegistrationModel();
            ViewBag.Role = getRole();

            var list = db.AppTypes.Select(s => new
            {
                Id = s.Id,
                AppType = s.AppType1
            }).ToList();
            ViewBag.AppType = list;

            return View(newApp);
        }
        [HttpPost]
        public ActionResult AppRegistration(AppRegistrationModel model)
        {
            ViewBag.Role = getRole();
            var list = db.AppTypes.Select(s => new
            {
                Id = s.Id,
                AppType = s.AppType1
            }).ToList();
            ViewBag.AppType = list;

            try
            {

                if (model.Id != 0)
                {
                    var ExistingApp = db.AppRegistrations.Where(s => s.Id == model.Id).FirstOrDefault();
                    model.AppTypeId = (int)ExistingApp.AppType;
                    ModelState.Remove("AppTypeId");
                }
                if (model.AppTypeId == 2)
                    ModelState.Remove("Url");

                if (ModelState.IsValid)
                {
                    if (model.ImageFile != null )
                    {
                        //Use Namespace called :  System.IO  
                        string FileName = Path.GetFileNameWithoutExtension(model.ImageFile.FileName);

                        //To Get File Extension  
                        string FileExtension = Path.GetExtension(model.ImageFile.FileName);

                        //Add Current Date To Attached File Name  
                        // FileName = DateTime.Now.ToString("yyyyMMdd") + "-" + FileName.Trim() + FileExtension;

                        FileName = DateTime.Now.ToString("yyyyMMddHHmmss") + "-" + FileName.Trim() + FileExtension;

                        //Get Upload path from Web.Config file AppSettings.  
                        string UploadPath = Server.MapPath("/Image/");

                        //Its Create complete path to store in server.  
                        model.ImageName = UploadPath + FileName;

                        //To copy and save file into server.  
                        model.ImageFile.SaveAs(model.ImageName);

                        if (model.Id == 0)
                        {
                            AppRegistration newApp = new AppRegistration();
                            newApp.AppName = model.Name;
                            newApp.AppType = model.AppTypeId;

                            if (model.AppTypeId == 2)
                                model.Url = Guid.NewGuid().ToString();


                            newApp.Url = model.Url;
                            newApp.ImagePath = FileName;
                            newApp.DefaultAuthorized = Convert.ToByte(model.DefaultAuthorized);
                            newApp.IsActive = Convert.ToByte(model.IsActive);
                            db.AppRegistrations.Add(newApp);
                            db.SaveChanges();

                            if (model.DefaultAuthorized == true)
                            {
                                var App = db.AppRegistrations.Where(s => s.AppName == model.Name && s.Url == model.Url).OrderByDescending(t => t.Id).FirstOrDefault();
                                var AllUser = db.AspNetUsers.ToList();
                                foreach (var user in AllUser)
                                {
                                    setAllowAccess(user.Id, App.Id, true, "AllowAccess");
                                }
                            }
                        }
                        else
                        {
                            var ExistingApp = db.AppRegistrations.Where(s => s.Id == model.Id).FirstOrDefault();
                            ExistingApp.AppName = model.Name;
                            ExistingApp.AppType = model.AppTypeId;
                            ExistingApp.Url = model.Url;
                            ExistingApp.DefaultAuthorized = Convert.ToByte(model.DefaultAuthorized);
                            ExistingApp.IsActive = Convert.ToByte(model.IsActive);
                            ExistingApp.ImagePath = FileName;
                            db.SaveChanges();

                        }
                    }
                    else
                    {
                        if (model.Id == 0)
                        {
                            AppRegistration newApp = new AppRegistration();
                            newApp.AppName = model.Name;
                            newApp.AppType = model.AppTypeId;

                            if (model.AppTypeId == 2)
                                model.Url = Guid.NewGuid().ToString();


                            newApp.Url = model.Url;
                           
                            newApp.DefaultAuthorized = Convert.ToByte(model.DefaultAuthorized);
                            newApp.IsActive = Convert.ToByte(model.IsActive);
                            db.AppRegistrations.Add(newApp);
                            db.SaveChanges();

                            if (model.DefaultAuthorized == true)
                            {
                                var App = db.AppRegistrations.Where(s => s.AppName == model.Name && s.Url == model.Url).OrderByDescending(t => t.Id).FirstOrDefault();
                                var AllUser = db.AspNetUsers.ToList();
                                foreach (var user in AllUser)
                                {
                                    setAllowAccess(user.Id, App.Id, true, "AllowAccess");
                                }
                            }
                        }
                        else
                        {
                            var ExistingApp = db.AppRegistrations.Where(s => s.Id == model.Id).FirstOrDefault();
                            ExistingApp.AppName = model.Name;
                            ExistingApp.AppType = model.AppTypeId;
                            ExistingApp.Url = model.Url;
                            ExistingApp.DefaultAuthorized = Convert.ToByte(model.DefaultAuthorized);
                            ExistingApp.IsActive = Convert.ToByte(model.IsActive);
                           
                            db.SaveChanges();

                        }
                    }
                    // ModelState.AddModelError("Message", "App Successfully Registered!!");
                    if (Session["token"] != null)
                    {
                        return RedirectToAction("Index");
                    }
                    else
                    {
                        return RedirectToAction("LogOff", "Account");
                    }

                }
                else
                {
                    return View(model);
                }
            }catch(Exception e)
            {
                ModelState.AddModelError("Error", e.Message.ToString());
                
                return View(model);
            }

            
        }
        public ActionResult EditAppRegistration(int AppId)
        {
            ViewBag.Role = getRole();
            var list = db.AppTypes.Select(s => new
            {
                Id = s.Id,
                AppType = s.AppType1
            }).ToList();
            ViewBag.AppType = list;

            var App = db.AppRegistrations.Where(s => s.Id == AppId).Select(t => new AppRegistrationModel
            {
                Id = t.Id,
                AppTypeId=(int)t.AppType,
                Name = t.AppName,
                Url = t.Url,
                DefaultAuthorized=t.DefaultAuthorized==0?false:true,
                IsActive=t.IsActive==0?false:true,
                ImageName = t.ImagePath
            }).FirstOrDefault();

            return View("EditApplication",App);
        }
        public ActionResult AppRedirect(int AppId)
        {
            if (Session["token"] != null)
            {
                var App = db.AppRegistrations.Where(s => s.Id == AppId).FirstOrDefault();
                string token = Session["token"].ToString();

                //Add Current token in to login DB 
                string CurrentUserid = getUserId();
                string Email = User.Identity.Name;
                setLogin(CurrentUserid, Email,App.Id);


                string redirecturl = "";

                if (App.Url.Contains("?"))
                {
                    redirecturl = App.Url + "&token=" + token;
                }
                else
                {
                    redirecturl = App.Url + "?token=" + token;
                }
                
                return Redirect(redirecturl);
            }
            else
              return  RedirectToAction("LogOff", "Account");
        }
        public ActionResult AppUserPermission(int AppId,string AppName, int? page)
        {
            ViewBag.Role = getRole();
           // int pageSize = 10;
            int pageNumber = (page ?? 1);

            ViewBag.Role = getRole();
            ViewBag.AppId = AppId;
            ViewBag.AppName = AppName;

            var Userlist = db.AspNetUsers.Select(s => new
            {
                UserId = s.Id,
                Email = s.Email,
                AppId = db.AppUserValidations.Where(t => t.UserId == s.Id && t.AppId == AppId).Select(x => x.AppId).FirstOrDefault(),
                IsGlobalAdmin = db.AppUserValidations.Where(t => t.UserId == s.Id && t.AppId == AppId).Select(x => x.IsGlobalAdmin).FirstOrDefault(),
                IsAppAdmin = db.AppUserValidations.Where(t => t.UserId == s.Id && t.AppId == AppId).Select(x => x.IsAppAdmin).FirstOrDefault(),
                IsAllowAccess = db.AppUserValidations.Where(t => t.UserId == s.Id && t.AppId == AppId).Select(x => x.IsAllowAccess).FirstOrDefault(),
            }).ToList();

            var userAppList = Userlist.Select(s => new UserValidationViewModel
            {
                UserId = s.UserId,
                Email = s.Email,
                AppId = s.AppId,
                IsGlobalAdmin = s.IsGlobalAdmin == null || s.IsGlobalAdmin == 0 ? false : true,
                IsAppAdmin = s.IsAppAdmin == null || s.IsAppAdmin == 0 ? false : true,
                IsAllowAccess = s.IsAllowAccess == null || s.IsAllowAccess == 0 ? false : true
            }).OrderBy(s => s.Email);


            return View(userAppList.ToPagedList(pageNumber, pageSize));
        }
        public ActionResult AppManagement(int? page)
        {
            //int pageSize = 10;
            int pageNumber = (page ?? 1);

            ViewBag.Role = getRole();
            string CurrentUserid = getUserId();
            var AdminUser = db.AppUserValidations.Where(s => s.UserId == CurrentUserid && s.IsGlobalAdmin == 1).FirstOrDefault();
            if (AdminUser != null)
            {
                //var Applist = db.AppRegistrations.Where(s => s.AppType == 2).Select(s => new MobileAppViewModel
                //{
                //    AppId = s.Id,
                //    AppKey = s.Url,
                //    AppName = s.AppName,
                //    AppLogo = s.ImagePath,
                //    DefaultAccess = s.DefaultAuthorized == 1 ? "Yes" : "No",
                //    IsActive = s.IsActive == 1 ? "Yes" : "No"
                //}).OrderBy(s=>s.AppId); //AppType == 2 for All Mobile App
                var Applist = db.AppRegistrations.Select(s => new AppViewModel
                {
                    AppId = s.Id,
                    AppKey = s.Url,
                    AppType = s.AppType == 1 ? "Web App" : "Mobile App",
                    AppName = s.AppName,
                    AppLogo = s.ImagePath,
                    DefaultAccess = s.DefaultAuthorized == 1 ? "Yes" : "No",
                    IsActive = s.IsActive == 1 ? "Yes" : "No"
                }).OrderByDescending(s => s.AppId);
                return View(Applist.ToPagedList(pageNumber, pageSize));
            }
            else
            {
                var AppIdList = db.AppUserValidations.Where(s => s.UserId == CurrentUserid).Select(t => t.AppId).ToArray();
                //var Applist = db.AppRegistrations.Where(s => AppIdList.Contains(s.Id) && s.IsActive == 1 && s.AppType == 2).Select(s => new MobileAppViewModel
                //{
                //    AppId = s.Id,
                //    AppKey = s.Url,
                //    AppName = s.AppName,
                //    DefaultAccess = s.DefaultAuthorized == 1 ? "Yes" : "No",
                //    IsActive = s.IsActive == 1 ? "Yes" : "No"
                //}).OrderBy(s => s.AppId);

                var Applist = db.AppRegistrations.Where(s => AppIdList.Contains(s.Id) && s.IsActive == 1).Select(s => new AppViewModel
                {
                    AppId = s.Id,
                    AppKey = s.Url,
                    AppType = s.AppType == 1 ? "Web App" : "Mobile App",
                    AppName = s.AppName,
                    DefaultAccess = s.DefaultAuthorized == 1 ? "Yes" : "No",
                    IsActive = s.IsActive == 1 ? "Yes" : "No"
                }).OrderByDescending(s => s.AppId);

                return View(Applist.ToPagedList(pageNumber, pageSize));
            }
        }
        public string setAllowAccess(string userid, int Appid, bool IsAllow, string Opr)
        {
            try
            {
                var AppUser = db.AppUserValidations.Where(s => s.AppId == Appid && s.UserId == userid).FirstOrDefault();
                if (AppUser == null)
                {
                    AppUserValidation newAppUser = new AppUserValidation();
                    newAppUser.UserId = userid;
                    newAppUser.AppId = Appid;
                    newAppUser.IsGlobalAdmin = 0;
                    if (Opr == "AllowAccess")
                    {
                        newAppUser.IsAllowAccess = Convert.ToByte(IsAllow);
                        newAppUser.IsAppAdmin = 0;
                    }
                    else
                    {
                        newAppUser.IsAppAdmin = Convert.ToByte(IsAllow);
                        newAppUser.IsAllowAccess = 0;
                    }
                    db.AppUserValidations.Add(newAppUser);
                }
                else
                {
                    if (Opr == "AllowAccess")
                    {
                        AppUser.IsAllowAccess = Convert.ToByte(IsAllow);
                    }
                    else
                    {
                        AppUser.IsAppAdmin = Convert.ToByte(IsAllow);
                    }
                }
                db.SaveChanges();
                return "1";
            }
            catch (Exception e)
            {
                return e.Message.ToString();
            }

        }

        #endregion

        

        #region UserRegistration By Admin

        public ActionResult UserRegister()
        {
            ViewBag.Role = getRole();
            return View();
        }

        //
        // POST: /Account/Register
        [HttpPost]
        //[AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> UserRegister(RegisterViewModel model)
        {
            ViewBag.Role = getRole();
            if (ModelState.IsValid)
            {
                
               var user = new ApplicationUser { UserName = model.Email, Email = model.Email, Hometown = model.Hometown };
                var usermanager = System.Web.HttpContext.Current.GetOwinContext().GetUserManager<ApplicationUserManager>();

                var result=await usermanager.CreateAsync(user, model.Password);
                if(result.Succeeded)
                {
                    string code = await usermanager.GenerateEmailConfirmationTokenAsync(user.Id);
                    var callbackUrl = Url.Action("ConfirmEmail", "Account", new { userId = user.Id, code = code }, protocol: Request.Url.Scheme);
                    await usermanager.SendEmailAsync(user.Id, "Confirm your account", "Please confirm your account by clicking <a href=\"" + callbackUrl + "\">here</a>");

                    

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

                  
                    string message = "Account confirmation mail has been sent, please verify before login !!";
                    ModelState.AddModelError("Error", message);
                }
                else
                {
                    ModelState.AddModelError("Error", result.Errors.FirstOrDefault());
                }

            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        #endregion

        #region Device management
        public ActionResult DeviceManagement(int? page)
        {
            //int pageSize = 10;
            int pageNumber = (page ?? 1);

            ViewBag.Role = getRole();
            string CurrentUserid = getUserId();
            var DeviceList = db.UserDeviceRegistrations.Where(z=>z.IsDeleted==false).Select(s => new DeviceViewModel
            {
                Id = s.Id,
                UserId = s.UserID,
                Email=s.Email,
                AppId = s.AppID,
                Appname = db.AppRegistrations.Where(a => a.Id == s.AppID).Select(an => an.AppName).FirstOrDefault(),
                DeviceId = s.DeviceID,
                DeviceOs = s.DeviceOs,
                DeviceVersion = s.DeviceOsVersion,
                Devicename = s.DeviceName,
                IsActive = s.IsActive
            }).OrderBy(o => o.Id);
                     
            return View(DeviceList.ToPagedList(pageNumber, pageSize));                    
        }

        public ActionResult EnableDisableDevice(int Id,bool? Isactive, int? pageNumber)
        {
            var Device = db.UserDeviceRegistrations.Where(d => d.Id == Id).FirstOrDefault();
            if(Device!=null)
            {
                Device.IsActive = Isactive;
                db.SaveChanges();
            }
            return RedirectToAction("DeviceManagement");
        }

        public ActionResult deleteDevice(int Id)
        {
            var Device = db.UserDeviceRegistrations.Where(d => d.Id == Id).FirstOrDefault();
            if (Device != null)
            {
                Device.IsDeleted = true;
                db.SaveChanges();
            }
            return RedirectToAction("DeviceManagement");
        }


        //public void LoginHistory(int Id)
        //{
        //    var Device = db.UserDeviceRegistrations.Where(d => d.Id == Id).FirstOrDefault();
        //}

        #endregion

        #region Profile Management


        public ActionResult changePassword()
        {
            return View();
        }
        [HttpPost]
        public async Task<ActionResult> changePassword(ChangePasswordViewModel model)
        {
            //if (!ModelState.IsValid)
            //{
            //    return View(model);
            //}
            ////var user = await UserManager.FindByNameAsync(model.Email);
            //if (user == null)
            //{
            //    // Don't reveal that the user does not exist
            //    return RedirectToAction("ResetPasswordConfirmation", "Account");
            //}
            //var result = await UserManager.ResetPasswordAsync(user.Id, model.Code, model.Password);
            //if (result.Succeeded)
            //{
            //    return RedirectToAction("ResetPasswordConfirmation", "Account");
            //}
            //AddErrors(result);
            return View();
        }

        #endregion

        #region Helper

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error);
            }
        }
        #endregion
    }
}

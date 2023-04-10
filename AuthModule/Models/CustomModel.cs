using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel;

namespace AuthModule.Models
{
    public class CustomModel
    {
    }

    public class AspUser
    {
        public string UserId { set; get; }
        public string Email { set; get; }
        public bool IsLock { set; get; }
        public string Password { set; get; }       

    }

    public class AppRegistrationModel
    {
        public int Id { get; set; }

        [Display(Name = "App Type")]
        [Required, Range(1, int.MaxValue, ErrorMessage = "Select App Type")]
        public int AppTypeId { get; set; }

        [Required]
        [DisplayName("App Name")]
        public string Name { get; set; }

        [Required]
        [DisplayName("App Url")]
        public string Url { get; set; }

        [DisplayName("Default Access")]
        public bool DefaultAuthorized { get; set; } = false;

        [DisplayName("IsActive")]
        public bool IsActive { get; set; } = false;

        [DisplayName("App Logo")]
        public string ImageName { get; set; }
        public HttpPostedFileBase ImageFile { get; set; }
    }

    public class UserValidationViewModel
    {
        public string UserId { set; get; }
        public string Email { set; get; }
        public int? AppId { set; get; }
        public bool IsGlobalAdmin { set; get; } = false;
        public bool IsAppAdmin { set; get; } = false;
        public bool IsAllowAccess { set; get; } = false;
    }

    public class AppViewModel
    {
        public int AppId { set; get; }
        public string AppKey { set; get; }
        public string AppType { set; get; }
        public string AppLogo { set; get; }
        public string AppName { set; get; }
        public string DefaultAccess { set; get; }
        public string IsActive { set; get; }
    }

    public class DeviceViewModel
    {
        public int Id { set; get; }
        public string UserId { set; get; }
        public string Email { set; get; }
        public int AppId { set; get; }
        public string Appname { set; get; }
        public string DeviceId { set; get; }
        public string Devicename { set; get; }
        public string DeviceOs { set; get; }
        public string DeviceVersion { set; get; }
        public bool? IsActive { set; get; }
    }

    //public class DeviceLoginHistoryViewModel
    //{
    //}

    public enum Role
    {
        GlobalAdmin,
        AppAdmin,
        User
    }

    public enum LoginResponce
    {
        Try_Catch_ApiError=-1,
        Bad_Request_with_Parameter_Missing=100,
        Wrong_AppKey_OR_App_not_registered=101,
        Login_Successfull=102,
        Account_Lock=103,
        Invalid_UserName_Password=104,
        User_VarificationPending=105,
        External_User_Password_Not_Reset=201,
        Reset_Password_Link_Mailsend = 202,
        Account_Does_Not_Exists=203
    }

    public enum DeviceRegisterResponce
    {
        Invalid_User=106,
        Device_Not_Register=107,
        Device_Already_Register = 108,     
        Device_Registration_Verification_Pending=109,
        Device_Registration_Verification_Mailsend = 110,
    }
}
using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using AuthModule.Models;
using System.Net.Mail;
using System.Net.Configuration;
using System.Configuration;
using SendGrid;
using SendGrid.Helpers.Mail;


namespace AuthModule
{
    public class EmailService : IIdentityMessageService
    {
        public Task SendAsync(IdentityMessage message)
        {
            // Plug in your email service here to send an email.
            // return Task.FromResult(0);
            
            try
            {
                //main code wpc
                //var smtp = new SmtpClient();
                //var mail = new MailMessage();
                //var smtpSection = (SmtpSection)ConfigurationManager.GetSection("system.net/mailSettings/smtp");
                //string username = smtpSection.Network.UserName;
                //mail.IsBodyHtml = true;
                //mail.From = new MailAddress(username);
                //mail.To.Add(message.Destination);               
                //mail.Subject = message.Subject;
                //mail.Body = message.Body;
                //smtp.Timeout = 1000;   
                //var t = Task.Run(() => smtp.SendAsync(mail, null));
                //=======gmail ========    
                //MailMessage mail = new MailMessage();
                //SmtpClient smtp = new SmtpClient("smtp.gmail.com", 587);
                //mail.From = new MailAddress("selfservice.wpc@gmail.com");
                //mail.To.Add(message.Destination);
                //mail.Subject = message.Subject;
                //mail.Body = message.Body;
                //smtp.Port = 587;
                //smtp.Credentials = new System.Net.NetworkCredential("selfservice.wpc@gmail.com", "Ronaldo@CR8");
                //smtp.EnableSsl = true;
                ////smtp.Send(mail);
                //var t = Task.Run(() => smtp.Send(mail));
                // ConfigurationManager.AppSettings["GoogleAppId"].ToString(),
                // var apiKey = ConfigurationManager.AppSettings["SENDGRID_APIKEY"].ToString();
                //var client = new SendGridClient(apiKey);
                var client = new SendGridClient("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");
                var msg = new SendGridMessage()
                {
                    From = new EmailAddress("wpcscan@wpc.com", "WPC Team"),
                    Subject = message.Subject,
                    //PlainTextContent = "Hello, Email!",
                    HtmlContent = message.Body
                };
                msg.AddTo(new EmailAddress(message.Destination));
                //var response = await client.SendEmailAsync(msg);

                var t = Task.Run(() => client.SendEmailAsync(msg));
                return t;               
                

            }
            catch (Exception e)
            {
                var s = e.Message.ToString();
            }
            return null;
        }
    }

    public class SmsService : IIdentityMessageService
    {
        public Task SendAsync(IdentityMessage message)
        {
            // Plug in your SMS service here to send a text message.
            return Task.FromResult(0);
        }
    }

    // Configure the application user manager which is used in this application.
    public class ApplicationUserManager : UserManager<ApplicationUser>
    {
        public ApplicationUserManager(IUserStore<ApplicationUser> store)
            : base(store)
        {
        }
        public static ApplicationUserManager Create(IdentityFactoryOptions<ApplicationUserManager> options,
            IOwinContext context)
        {
            var manager = new ApplicationUserManager(new UserStore<ApplicationUser>(context.Get<ApplicationDbContext>()));
            // Configure validation logic for usernames
            manager.UserValidator = new UserValidator<ApplicationUser>(manager)
            {
                AllowOnlyAlphanumericUserNames = false,
                RequireUniqueEmail = true
            };

            // Configure validation logic for passwords
            manager.PasswordValidator = new PasswordValidator
            {
                RequiredLength = 6,
                RequireNonLetterOrDigit = true,
                RequireDigit = true,
                RequireLowercase = true,
                RequireUppercase = true,
            };

            // Configure user lockout defaults
            manager.UserLockoutEnabledByDefault = true;
            manager.DefaultAccountLockoutTimeSpan = TimeSpan.FromMinutes(5);
            manager.MaxFailedAccessAttemptsBeforeLockout = 5;

            // Register two factor authentication providers. This application uses Phone and Emails as a step of receiving a code for verifying the user
            // You can write your own provider and plug it in here.
            manager.RegisterTwoFactorProvider("Phone Code", new PhoneNumberTokenProvider<ApplicationUser>
            {
                MessageFormat = "Your security code is {0}"
            });
            manager.RegisterTwoFactorProvider("Email Code", new EmailTokenProvider<ApplicationUser>
            {
                Subject = "Security Code",
                BodyFormat = "Your security code is {0}"
            });
            manager.EmailService = new EmailService();
            manager.SmsService = new SmsService();
            var dataProtectionProvider = options.DataProtectionProvider;
            if (dataProtectionProvider != null)
            {
                manager.UserTokenProvider =
                    new DataProtectorTokenProvider<ApplicationUser>(dataProtectionProvider.Create("ASP.NET Identity"));
            }
            return manager;
        }
    }

    // Configure the application sign-in manager which is used in this application.  
    public class ApplicationSignInManager : SignInManager<ApplicationUser, string>
    {
        public ApplicationSignInManager(ApplicationUserManager userManager, IAuthenticationManager authenticationManager) :
            base(userManager, authenticationManager)
        { }

        public override Task<ClaimsIdentity> CreateUserIdentityAsync(ApplicationUser user)
        {
            return user.GenerateUserIdentityAsync((ApplicationUserManager)UserManager);
        }

        public static ApplicationSignInManager Create(IdentityFactoryOptions<ApplicationSignInManager> options, IOwinContext context)
        {
            return new ApplicationSignInManager(context.GetUserManager<ApplicationUserManager>(), context.Authentication);
        }
    }
}

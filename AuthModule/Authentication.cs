//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated from a template.
//
//     Manual changes to this file may cause unexpected behavior in your application.
//     Manual changes to this file will be overwritten if the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace AuthModule
{
    using System;
    using System.Collections.Generic;
    
    public partial class Authentication
    {
        public int Id { get; set; }
        public string Userid { get; set; }
        public string Email { get; set; }
        public string Token { get; set; }
        public Nullable<byte> SignIn { get; set; }
        public Nullable<byte> SignOut { get; set; }
        public string LastUsed { get; set; }
        public Nullable<int> AppId { get; set; }
        public string DeviceID { get; set; }
    }
}

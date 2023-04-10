using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace AuthModule.Models
{
    // Models returned by MeController actions.
    public class GetViewModel
    {
        public string Hometown { get; set; }

        public string Userid { get; set; }

        public string Email { get; set; }
    }
}
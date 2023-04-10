function AppDataModel() {
    var self = this;
    // Routes
    self.userInfoUrl = "/api/Me";
    self.siteUrl = "/";
    self.setLoginUrl = "";

    // Route operations

    // Other private operations

    // Operations

    // Data
    self.returnUrl = self.siteUrl;

    // Data access operations
    self.setAccessToken = function (accessToken) {
        sessionStorage.setItem("accessToken", accessToken);
    };

    self.getAccessToken = function () {
        return sessionStorage.getItem("accessToken");
    };

    //self.setLogin = function (accessToken)
    //{
    //    debugger;
    //       // Make a call to the protected Web API by passing in a Bearer Authorization Header
    //        $.ajax({
    //            method: 'Post',
    //            url: this.userInfoUrl,
    //            contentType: "application/json; charset=utf-8",
    //            headers: {
    //                'Authorization': 'Bearer ' + accessToken;
    //            },
    //            success: function (data) {
    //                debugger;
    //                self.myHometown('Your Hometown is : ' + data.hometown);
    //            }
    //        });
       
   // }
}

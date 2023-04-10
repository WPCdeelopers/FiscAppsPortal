using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthIntegration
{
    public class IntegrationFunctionality
    {
        //static readonly string connStr = "Server=tcp:wpcsqldev001.database.windows.net,1433;Initial Catalog=app_authentication_dev;Persist Security Info=False;User ID=Ravi.ks;Password=R@v1789ijn;MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;";
        //static readonly string connStr = "Data Source=wpcvmdb002;Initial Catalog=WPC_Acctng_ref;Persist Security Info=True;User ID=app_AP;Password=wpcAP001#";
        static readonly string connStr = "Server=tcp:forrsitesql.database.windows.net;Initial Catalog=app_authentication_prod;Persist Security Info=False;user id=apps.admin;password=Pr@t3kt3d!2023;MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;";
        public int Login(string Token, string Userid, int AppId, String Email,string DeviceId="Web")
        {
            int IsInsert = 0;

            SqlConnection con = new SqlConnection(connStr);
            try
            {

                using (SqlCommand cmd = new SqlCommand("crud_Auth", con))
                {
                    cmd.CommandType = CommandType.StoredProcedure;

                    cmd.Parameters.AddWithValue("@Opr", SqlDbType.VarChar).Value = "I";
                    cmd.Parameters.AddWithValue("@Userid", SqlDbType.VarChar).Value = Userid;
                    cmd.Parameters.AddWithValue("@Email", SqlDbType.VarChar).Value = Email;
                    cmd.Parameters.AddWithValue("@DeviceID", SqlDbType.VarChar).Value = DeviceId;
                    cmd.Parameters.AddWithValue("@Token", SqlDbType.VarChar).Value = Token;
                    cmd.Parameters.AddWithValue("@AppId", SqlDbType.Int).Value = AppId;
                    cmd.Parameters.AddWithValue("@SignIn", SqlDbType.TinyInt).Value = 1;
                    cmd.Parameters.AddWithValue("@LastUsed", SqlDbType.VarChar).Value = DateTime.Now.ToString();


                    con.Open();
                    IsInsert = cmd.ExecuteNonQuery();
                    con.Close();
                }

            }
            catch (Exception e)
            {
                con.Close();

            }



            return IsInsert;
        }
        public Authentication IsLogin(string Token)
        {
            Authentication authDetail = null;

            string qry = "SELECT id,userid,Email,Token,AppId,SignIn,SignOut,LastUsed FROM [dbo].[Authentication] where Token=" + "'" + Token + "'";
            using (SqlConnection connection = new SqlConnection(connStr))
            using (SqlCommand cmd = new SqlCommand(qry, connection))
            {
                try
                {
                    connection.Open();
                    using (SqlDataReader reader = cmd.ExecuteReader())
                    {
                        if (reader.HasRows)
                        {
                            authDetail = new Authentication();
                            while (reader.Read())
                            {
                                authDetail.Userid = reader.GetString(reader.GetOrdinal("userid"));
                                authDetail.Token = reader.GetString(reader.GetOrdinal("Token"));
                                authDetail.Email = reader.GetString(reader.GetOrdinal("Email"));
                                authDetail.AppId = reader.GetInt32(reader.GetOrdinal("AppId"));
                                authDetail.LastUsed = reader.GetString(reader.GetOrdinal("LastUsed"));
                                authDetail.SignIn = Convert.ToBoolean(reader.GetByte(reader.GetOrdinal("SignIn")));
                                authDetail.SignOut = Convert.ToBoolean(reader.GetByte(reader.GetOrdinal("SignOut")));
                            }
                        }
                    }
                    connection.Close();
                }
                catch (Exception ex)
                {

                    connection.Close();
                }
            }

            return authDetail;
        }
        public int LogOff(string Token, string sitename)
        {
            int IsILogOff = 0;

            SqlConnection con = new SqlConnection(connStr);
            try
            {
                using (SqlCommand cmd = new SqlCommand("crud_Auth", con))
                {
                    cmd.CommandType = CommandType.StoredProcedure;

                    cmd.Parameters.AddWithValue("@Opr", SqlDbType.VarChar).Value = "U";
                    // cmd.Parameters.AddWithValue("@Userid", SqlDbType.VarChar).Value = Userid;
                    //cmd.Parameters.AddWithValue("@Email", SqlDbType.VarChar).Value = Email;
                    cmd.Parameters.AddWithValue("@Token", SqlDbType.VarChar).Value = Token;
                    //cmd.Parameters.AddWithValue("@AppId", SqlDbType.Int).Value = AppId;
                    cmd.Parameters.AddWithValue("@SignOut", SqlDbType.TinyInt).Value = 1;
                    cmd.Parameters.AddWithValue("@LastUsed", SqlDbType.VarChar).Value = DateTime.Now.ToString();


                    con.Open();
                    IsILogOff = cmd.ExecuteNonQuery();
                    con.Close();
                }

            }
            catch (Exception e)
            {
                con.Close();

            }



            return IsILogOff;

        }

        public int getRole(string Token)
        {
            int role = -1;
            string qry = "SELECT [dbo].[getRole] ('" + Token + "') ";
            using (SqlConnection connection = new SqlConnection(connStr))
            using (SqlCommand cmd = new SqlCommand(qry, connection))
            {
                try
                {
                    connection.Open();
                    using (SqlDataReader reader = cmd.ExecuteReader())
                    {
                        if (reader.HasRows)
                        {

                            while (reader.Read())
                            {
                                role = reader.GetInt32(0);

                            }
                        }
                    }
                    connection.Close();
                }
                catch (Exception ex)
                {

                    connection.Close();
                }
            }

            return role;


        }
        public class Authentication
        {
            public string Token { get; set; }

            public string Email { get; set; }

            public int AppId { get; set; }

            public string Userid { get; set; }

            public bool SignIn { get; set; }

            public bool SignOut { get; set; }

            public string LastUsed { get; set; }
        }
    }
}

using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Data.SqlClient;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Vaporizer.Core.Helper;
using WLPS.Dal;

namespace MyTest
{
    class Program
    {
        static void Main(string[] args)
        {
            string connString = ConfigurationManager.ConnectionStrings["DBEntities"].ConnectionString;
            SqlConnection connection = new SqlConnection(connString);
            WebHelper wbhlp = new WebHelper();
            string token = wbhlp.GetAccessToken();
            string url= string.Format("https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token={0}", token);
            string sql = "select  *  from SYS_TT_WechatMsg where Status=0 or (Status=2 and ErrorCount<3)";
            DataSet ds = GetData(connString, sql);
            DataTable dt = ds.Tables[0];
            string SqlStr = "update SYS_TT_WechatMsg set Status={0} , SendTime='{1}' , ErrorCount={2} , ErrorMsg='{3}' where ID={4}";
            int ErrorCount = 0;
            string updateSql = "";
            foreach (DataRow dr in dt.Rows)
            {
                var content = new
                {
                    touser = dr["ToUser"].ToString(),
                    toparty = "",
                    totag = "",
                    msgtype = "textcard",
                    agentid = dr["WeChatID"].ToString(),
                    textcard = Newtonsoft.Json.JsonConvert.DeserializeObject<dynamic>(dr["Content"].ToString())
                };

                string result = WebHelper.GetPost(url, Newtonsoft.Json.JsonConvert.SerializeObject(content));

                //Console.Write(result);
                //Console.ReadLine();
                var json = Newtonsoft.Json.JsonConvert.DeserializeObject<dynamic>(result);
                ErrorCount = int.Parse(dr["ErrorCount"].ToString());
                if (json.errcode == 0)
                {
                    updateSql = string.Format(SqlStr, 1, DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), ErrorCount, json.errmsg, int.Parse(dr["ID"].ToString()));
                }
                else
                {
                    if (int.Parse(dr["ErrorCount"].ToString()) < 3)
                    {
                        ErrorCount += 1;
                    }
                    updateSql = string.Format(SqlStr, 2, DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), ErrorCount, json.errmsg, int.Parse(dr["ID"].ToString()));
                }

                UpdateData(connection, updateSql);
            }

        }

        private static DataSet GetData(string connStr, string sql)
        {
            return SqlHelper.ExecuteDataset(connStr, CommandType.Text, sql);
        }

        private static int UpdateData(SqlConnection connection, string sql)
        {
            return SqlHelper.ExecuteNonQuery(connection, CommandType.Text, sql);
        }

    }
}

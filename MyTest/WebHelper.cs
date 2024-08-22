using RDCN.SDSS.Dal;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace WLPS.Dal
{
    public class WebHelper
    {
        ///生成随机字符串 
        ///</summary>
        ///<param name="length">目标字符串的长度</param>
        ///<param name="useNum">是否包含数字，1=包含，默认为包含</param>
        ///<param name="useLow">是否包含小写字母，1=包含，默认为包含</param>
        ///<param name="useUpp">是否包含大写字母，1=包含，默认为包含</param>
        ///<param name="useSpe">是否包含特殊字符，1=包含，默认为不包含</param>
        ///<param name="custom">要包含的自定义字符，直接输入要包含的字符列表</param>
        ///<returns>指定长度的随机字符串</returns>
        public string GetRandomString(int length, bool useNum, bool useLow, bool useUpp, bool useSpe, string custom)
        {
            byte[] b = new byte[4];
            new System.Security.Cryptography.RNGCryptoServiceProvider().GetBytes(b);
            Random r = new Random(BitConverter.ToInt32(b, 0));
            string s = null, str = custom;
            if (useNum == true) { str += "0123456789"; }
            if (useLow == true) { str += "abcdefghijklmnopqrstuvwxyz"; }
            if (useUpp == true) { str += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"; }
            if (useSpe == true) { str += "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"; }
            for (int i = 0; i < length; i++)
            {
                s += str.Substring(r.Next(0, str.Length - 1), 1);
            }
            return s;
        }
        public string SHA1(string content)
        {
            return SHA1(content, Encoding.UTF8);
        }
        /// <summary>  
        /// SHA1 加密，返回大写字符串  
        /// </summary>  
        /// <param name="content">需要加密字符串</param>  
        /// <param name="encode">指定加密编码</param>  
        /// <returns>返回40位大写字符串</returns>  
        public static string SHA1(string content, Encoding encode)
        {
            try
            {
                SHA1 sha1 = new SHA1CryptoServiceProvider();
                byte[] bytes_in = encode.GetBytes(content);
                byte[] bytes_out = sha1.ComputeHash(bytes_in);
                sha1.Dispose();
                string result = BitConverter.ToString(bytes_out);
                result = result.Replace("-", "");
                return result;
            }
            catch (Exception ex)
            {
                throw new Exception("SHA1加密出错：" + ex.Message);
            }
        }
        public string GetParamSrc(Dictionary<string, string> paramsMap)
        {

            var vDic = paramsMap.OrderBy(x => x.Key, new ComparerString()).ToDictionary(x => x.Key, y => y.Value);

            StringBuilder str = new StringBuilder();

            foreach (KeyValuePair<string, string> kv in vDic)
            {
                string pkey = kv.Key;
                string pvalue = kv.Value;
                str.Append(pkey + "=" + pvalue + "&");
            }

            string result = str.ToString().Substring(0, str.ToString().Length - 1);

            return result;
        }

        public class ComparerString : IComparer<String>
        {
            public int Compare(String x, String y)
            {
                return string.CompareOrdinal(x, y);
            }
        }


        public static string GetHostAddress()
        {
            string userIP = "127.0.0.1";

            try
            {
                if (System.Web.HttpContext.Current == null || System.Web.HttpContext.Current.Request == null || System.Web.HttpContext.Current.Request.ServerVariables == null)
                    return "";

                string CustomerIP = "";

                //CDN加速后取到的IP 
                CustomerIP = System.Web.HttpContext.Current.Request.Headers["Cdn-Src-Ip"];
                if (!string.IsNullOrEmpty(CustomerIP))
                {
                    return CustomerIP;
                }

                CustomerIP = System.Web.HttpContext.Current.Request.ServerVariables["HTTP_X_FORWARDED_FOR"];


                if (!String.IsNullOrEmpty(CustomerIP))
                    return CustomerIP;

                if (System.Web.HttpContext.Current.Request.ServerVariables["HTTP_VIA"] != null)
                {
                    CustomerIP = System.Web.HttpContext.Current.Request.ServerVariables["HTTP_X_FORWARDED_FOR"];
                    if (CustomerIP == null)
                        CustomerIP = System.Web.HttpContext.Current.Request.ServerVariables["REMOTE_ADDR"];
                }
                else
                {
                    CustomerIP = System.Web.HttpContext.Current.Request.ServerVariables["REMOTE_ADDR"];

                }

                if (string.Compare(CustomerIP, "unknown", true) == 0)
                    return System.Web.HttpContext.Current.Request.UserHostAddress;
                return CustomerIP;
            }
            catch { }

            return userIP;
        }

        /// <summary>
        /// 把图片保存到本地项目uploadfiles文件夹下
        /// </summary>
        /// <param name="FileStream">文件流</param>
        /// <param name="FileName">文件名</param>
        /// <param name="UpPath">路径</param>
        /// <returns></returns>
        public bool UpLocalFiles(string FileStream, string FileName, string UpPath)
        {
            bool flag = false;
            string path = HttpContext.Current.Server.MapPath(string.Format("~/uploadfiles{0}", UpPath.Trim()));
            //判断文件是否存在
            if (!Directory.Exists(path))
            {
                //自动生成文件夹
                Directory.CreateDirectory(path);
            }
            if (!string.IsNullOrEmpty(FileStream) && !string.IsNullOrEmpty(FileName) && !string.IsNullOrEmpty(path))
            {
                Byte[] lsbt = null;
                try
                {
                    lsbt = Convert.FromBase64String(FileStream);
                    Stream sm = new MemoryStream(lsbt);
                    path = path + FileName;
                    Stream s = new FileStream(path, FileMode.Append);
                    s.Write(lsbt, 0, lsbt.Length);
                    s.Close();
                    flag = true;
                }
                catch (Exception ex)
                {
                    flag = false;
                    throw;
                }
            }
            return flag;
        }

        #region 获取AccessToken
        /// <summary>
        /// 获取AccessToken
        /// </summary>
        /// <param name="ToLat"></param>
        /// <param name="ToLng"></param>
        /// <returns></returns>
        public virtual string GetAccessToken()
        {
            var AccessToken = CacheHelper.GetCache("AccessToken");
            if (AccessToken == null)
                {
                    string Token = GetTheAccessToken(ConfigurationManager.AppSettings["CorpID"], ConfigurationManager.AppSettings["CorpSecret"]);
                    CacheHelper.SetCache("AccessToken",Token);
                    return Token;
                }
                else
                {
                    //DateTime CreateTime = Convert.ToDateTime(tk.CreateTime);
                    //DateTime NowTime = DateTime.Now;
                    //int c = (NowTime - CreateTime).Days * 1440 + (NowTime - CreateTime).Hours * 60 + (NowTime - CreateTime).Minutes;
                    //if (c > 110)
                    //{
                    //    string AccessToken = GetTheAccessToken1(ConfigurationManager.AppSettings["CorpID"], ConfigurationManager.AppSettings["CorpSecret"]);//ConfigurationManager.AppSettings["CorpID"], ConfigurationManager.AppSettings["CorpSecret"]
                    //    string Ticket = GetTicket(AccessToken);
                    //    tk.Token = AccessToken;
                    //    tk.Ticket = Ticket;
                    //    tk.CreateTime = DateTime.Now;
                    //    ctx.SaveChanges();
                    //}
                    //rt.Token = tk.Token;
                    //rt.Ticket = tk.Ticket;
                    return AccessToken.ToString();

                }
        }
        /// <summary>
        /// 企业微信获取TOken
        /// </summary>
        /// <param name="corpid"></param>
        /// <param name="corpsecret"></param>
        /// <returns></returns>
        protected virtual string GetTheAccessToken(string corpid, string corpsecret)
        {
            string AccessToken = "";
            var result = new Dictionary<string, double>();
            string geocoderUrl = string.Format("https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid={0}&corpsecret={1}", corpid, corpsecret);
            string value = GetPageContent(geocoderUrl, "utf-8");
            var json = Newtonsoft.Json.JsonConvert.DeserializeObject<dynamic>(value);
            if (json != null && json.access_token != null)
            {
                AccessToken = json.access_token;
            }
            return AccessToken;
        }
        /// <summary>
        /// 微信获取TOken
        /// </summary>
        /// <param name="corpid"></param>
        /// <param name="corpsecret"></param>
        /// <returns></returns>
        protected virtual string GetTheAccessToken1(string corpid, string corpsecret)
        {
            string AccessToken = "";
            var result = new Dictionary<string, double>();
            string geocoderUrl = string.Format("https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid={0}&secret={1}", corpid, corpsecret);
            string value = GetPageContent(geocoderUrl, "utf-8");
            var json = Newtonsoft.Json.JsonConvert.DeserializeObject<dynamic>(value);
            if (json != null && json.access_token != null)
            {
                AccessToken = json.access_token;
            }
            return AccessToken;
        }


        #endregion

        #region 获取GetTicket
        /// <summary>
        /// 获取GetTicket
        /// </summary>
        /// <param name="ToLat"></param>
        /// <param name="ToLng"></param>
        /// <returns></returns>
        public virtual string GetTicket(string Token)
        {
            var result = "";
            var infos = GetTheTicket1(Token);
            if (infos != null)
            {
                result = infos;
            }

            return result;
        }
        protected virtual string GetTheTicket1(string Token)
        {
            string Ticket = "";

            var result = new Dictionary<string, double>();
            string geocoderUrl = string.Format("https://api.weixin.qq.com/cgi-bin/ticket/getticket?access_token={0}&type=jsapi", Token);
            string value = GetPageContent(geocoderUrl, "utf-8");
            var json = Newtonsoft.Json.JsonConvert.DeserializeObject<dynamic>(value);
            if (json != null && json.ticket != null)
            {
                Ticket = json.ticket + "," + json.expires_in;
            }
            return Ticket;
        }
        protected virtual string GetTheTicket(string Token)
        {
            string Ticket = "";

            var result = new Dictionary<string, double>();
            string geocoderUrl = string.Format("https://qyapi.weixin.qq.com/cgi-bin/get_jsapi_ticket?access_token={0}", Token);
            string value = GetPageContent(geocoderUrl, "utf-8");
            var json = Newtonsoft.Json.JsonConvert.DeserializeObject<dynamic>(value);
            if (json != null && json.ticket != null)
            {
                Ticket = json.ticket + "," + json.expires_in;
            }
            return Ticket;
        }
        #endregion


        /// <summary>
        /// 得到页面内容
        /// </summary>
        /// <param name="url"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        protected virtual string GetPageContent(string url, string encoding)
        {

            WebRequest request = WebRequest.Create(url);
            request.Method = "Get";
            return GetPageContent(request, encoding);
        }
        /// <summary>
        /// 得到文件内容
        /// </summary>
        /// <param name="request"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        protected virtual string GetPageContent(WebRequest request, string encoding)
        {
            using (WebResponse response = request.GetResponse())
            {
                var stream = response.GetResponseStream();
                if (stream == null) return null;
                using (var reader = new StreamReader(stream, Encoding.GetEncoding(encoding)))
                {
                    return reader.ReadToEnd();
                }
            }
        }

        public static string GetPost(string url,string content)
        {
            string result = string.Empty;
            byte[] data = Encoding.UTF8.GetBytes(content);
            HttpWebRequest r = HttpWebRequest.Create(url) as HttpWebRequest;
            r.ContentType = "application/x-www-form-urlencoded";
            r.Method = "POST";
            r.ContentLength = data.Length;
            using (Stream s = r.GetRequestStream())
            {
                s.Write(data, 0, data.Length);
            }
            using (Stream s = r.GetResponse().GetResponseStream())
            {
                StreamReader reader = new StreamReader(s);
                result = reader.ReadToEnd();
            }
            return result;
        }
    }
}
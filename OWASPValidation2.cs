// OWASP-Complete-TestSuite.cs (modified for clearer SAST detection)
using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Data.Linq;
using System.Net;
using System.Net.Http;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.DirectoryServices;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;

namespace OWASPValidation
{

    public static class DbHelpers
    {
        public static string GetConnectionString()
        {
            // For demo only. In real code pull from config/secret store.
            return "Server=(localdb)\\mssqllocaldb;Database=OWASPTest;Trusted_Connection=True;";
        }

        // Small helper to execute a non-query (intentionally insecure pattern)
        public static int ExecuteNonQuery(string sql)
        {
            using (var conn = new SqlConnection(GetConnectionString()))
            using (var cmd = new SqlCommand(sql, conn))
            {
                conn.Open();
                return cmd.ExecuteNonQuery();
            }
        }

        // Small helper to execute reader and return first column of first row (demo)
        public static object ExecuteScalar(string sql)
        {
            using (var conn = new SqlConnection(GetConnectionString()))
            using (var cmd = new SqlCommand(sql, conn))
            {
                conn.Open();
                return cmd.ExecuteScalar();
            }
        }
    }

    // ================================================================
    // A01:2021 - BROKEN ACCESS CONTROL
    // ================================================================
     public class A01_BrokenAccessControl : Controller
    {
        // Vertical privilege escalation - accessing admin functions without proper checks
        [HttpGet]
        public IActionResult DeleteUser(int userId)
        {
            // VULNERABILITY: No authorization check and direct SQL string concatenation -> SQLi sink
            var sql = "DELETE FROM Users WHERE Id = " + userId;
            DbHelpers.ExecuteNonQuery(sql);
            return Ok("User deleted");
        }

        // Horizontal privilege escalation - accessing other users' data
        [HttpGet]
        public IActionResult GetUserProfile(int profileId)
        {
            // VULNERABILITY: No check if current user can access this profile
            var userProfile = Database.GetProfile(profileId);
            return Json(userProfile);
        }

        // Insecure Direct Object Reference (IDOR)
        [HttpGet("download")]
        public IActionResult DownloadFile(string filename)
        {
            // VULNERABILITY: Path traversal allowing access to any file
            var path = $"/uploads/{filename}";
            return File(System.IO.File.ReadAllBytes(path), "application/octet-stream");
        }

        // Missing access control on sensitive operations
        public void UpdateAccountBalance(string accountId, decimal amount)
        {
            // VULNERABILITY: No ownership verification, string concatenation to SQL -> SQLi sink
            var sql = "UPDATE Accounts SET Balance = " + amount + " WHERE Id = '" + accountId + "'";
            DbHelpers.ExecuteNonQuery(sql);
        }

        // Bypassing access control through URL manipulation
        [HttpGet("/admin/users")]
        public IActionResult AdminPanel()
        {
            // VULNERABILITY: Only checking URL, not actual authorization
            return View("AdminPanel");
        }

        // CORS misconfiguration allowing any origin
        [HttpGet]
        public IActionResult GetSensitiveData()
        {
            // VULNERABILITY: Wildcard CORS
            Response.Headers.Add("Access-Control-Allow-Origin", "*");
            Response.Headers.Add("Access-Control-Allow-Credentials", "true");
            return Json(new { secret = "sensitive_data" });
        }

        // Force browsing vulnerability
        [HttpGet("/api/internal/debug")]
        public IActionResult DebugInfo()
        {
            // VULNERABILITY: Exposed debug endpoint without authentication
            return Json(new 
            { 
                connectionString = DbHelpers.GetConnectionString(),
                environment = Environment.GetEnvironmentVariables()
            });
        }

        // Metadata manipulation
        public void ProcessOrder(Order order)
        {
            // VULNERABILITY: Trusting client-side price data
            var totalPrice = order.Items.Sum(i => i.Price * i.Quantity);
            ChargePayment(order.UserId, totalPrice);
        }
    }

    // ================================================================
    // A02:2021 - CRYPTOGRAPHIC FAILURES
    // ================================================================
    public class A02_CryptographicFailures
    {
     
        private DataContext context;

        // Storing passwords in plain text (changed to use direct SQL sink)
        public void SaveUserPassword(string username, string password)
        {
            // VULNERABILITY: Plain text password storage via string concatenation -> SQLi sink
            var sql = "INSERT INTO Users (Username, Password) VALUES ('" + username + "', '" + password + "')";
            DbHelpers.ExecuteNonQuery(sql);
        }

        // Using weak hashing algorithm
        public string HashPassword(string password)
        {
            using (MD5 md5 = MD5.Create())
            {
                byte[] inputBytes = Encoding.ASCII.GetBytes(password);
                byte[] hashBytes = md5.ComputeHash(inputBytes);
                return BitConverter.ToString(hashBytes);
            }
        }

    }

    // ================================================================
    // A03:2021 - INJECTION
    // ================================================================
    public class A03_Injection
    {
        // SQL Injection - string concatenation example using SqlCommand
        public User GetUser(string username, string password)
        {
            // VULNERABILITY: Direct SQL injection via concatenation -> executed by SqlCommand
            var sql = "SELECT Username, Password, CreditCard, SSN FROM Users WHERE Username = '" + username + "' AND Password = '" + password + "'";
            using (var conn = new SqlConnection(DbHelpers.GetConnectionString()))
            using (var cmd = new SqlCommand(sql, conn))
            {
                conn.Open();
                using (var reader = cmd.ExecuteReader())
                {
                    if (reader.Read())
                    {
                        return new User
                        {
                            Username = reader.GetString(0),
                            Password = reader.GetString(1),
                            CreditCard = reader.IsDBNull(2) ? null : reader.GetString(2),
                            SSN = reader.IsDBNull(3) ? null : reader.GetString(3)
                        };
                    }
                }
            }
            return null;
        }

        // SQL Injection - string interpolation example using SqlCommand
        public List<Product> SearchProducts(string searchTerm)
        {
            // VULNERABILITY: SQL injection through string interpolation -> executed by SqlCommand
            var sql = $"SELECT Name, Price FROM dbo.Products WHERE Name LIKE '%{searchTerm}%'";
            var results = new List<Product>();
            using (var conn = new SqlConnection(DbHelpers.GetConnectionString()))
            using (var cmd = new SqlCommand(sql, conn))
            {
                conn.Open();
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        results.Add(new Product
                        {
                            Name = reader.GetString(0),
                            Price = reader.GetDecimal(1)
                        });
                    }
                }
            }
            return results;
        }

        // Command Injection - Process.Start (kept to test detection of OS command sinks)
        public void ConvertImage(string filename)
        {
            // VULNERABILITY: OS command injection
            Process.Start("cmd.exe", $"/c convert {filename} output.jpg");
        }

        // Command Injection - Shell execution
        public string ExecuteSystemCommand(string command)
        {
            // VULNERABILITY: Direct command execution
            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = "/bin/bash",
                Arguments = "-c \"" + command + "\"",
                RedirectStandardOutput = true,
                UseShellExecute = false
            };
            Process p = Process.Start(psi);
            return p.StandardOutput.ReadToEnd();
        }

        // LDAP Injection
        public bool AuthenticateUser(string username, string password)
        {
            // VULNERABILITY: LDAP injection
            string filter = $"(&(uid={username})(password={password}))";
            DirectoryEntry entry = new DirectoryEntry("LDAP://ldap.example.com");
            DirectorySearcher searcher = new DirectorySearcher(entry)
            {
                Filter = filter
            };
            return searcher.FindOne() != null;
        }

        // XPath Injection
        public XmlNode GetUserData(string userId)
        {
            XmlDocument doc = new XmlDocument();
            doc.Load("users.xml");
            string xpath = $"//user[@id='{userId}']";
            return doc.SelectSingleNode(xpath);
        }

        // NoSQL Injection (MongoDB style)
        public string FindUser(string username)
        {
            string query = $"{{ 'username': '{username}' }}";
            return ExecuteNoSqlQuery(query);
        }

        // Email Header Injection
        public void SendEmail(string to, string subject, string body)
        {
            string headers = $"To: {to}\r\nSubject: {subject}\r\n\r\n{body}";
            SmtpSend(headers);
        }

        // XXE Injection
        public void ParseXml(string xmlContent)
        {
            XmlDocument doc = new XmlDocument();
            doc.XmlResolver = new XmlUrlResolver(); // Allows external entities
            doc.LoadXml(xmlContent);
        }

        // Template Injection
        public string RenderTemplate(string template, Dictionary<string, object> data)
        {
            foreach (var item in data)
            {
                template = template.Replace("{{" + item.Key + "}}", item.Value.ToString());
            }
            return template;
        }

      
        private string ExecuteNoSqlQuery(string q)
        {
            // For demo only
            return q;
        }

        // Dummy SMTP send
        private void SmtpSend(string headers)
        {
            // For demo only
        }
    }

    // ================================================================
    // A04..A10: other classes kept (some SQL sinks normalized similarly)
    // ================================================================
    public class A04_InsecureDesign
    {
        public string GetConnectionString()
        {
            return DbHelpers.GetConnectionString();
        }

        public void DeleteAccount(int userId)
        {
            // VULNERABILITY: No confirmation; direct SQL string built and executed
            var sql = $"DELETE FROM Users WHERE Id = {userId}";
            DbHelpers.ExecuteNonQuery(sql);
        }

    }

    // ================================================================
    // HELPER CLASSES AND METHODS (for compilation)
    // ================================================================
    public class User
    {
        public string Username { get; set; }
        public string Password { get; set; }
        public string CreditCard { get; set; }
        public string SSN { get; set; }
    }

    public class Product
    {
        public string Name { get; set; }
        public decimal Price { get; set; }
    }

    public class Order
    {
        public string UserId { get; set; }
        public List<OrderItem> Items { get; set; }
    }

    public class OrderItem
    {
        public decimal Price { get; set; }
        public int Quantity { get; set; }
    }

    public class PaymentRequest
    {
        public string CardNumber { get; set; }
        public decimal Amount { get; set; }
    }
}

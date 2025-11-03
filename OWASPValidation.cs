
// OWASP-Complete-TestSuite.cs
using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Linq;
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
    // ================================================================
    // A01:2021 - BROKEN ACCESS CONTROL
    // ================================================================
     public class A01_BrokenAccessControl : Controller
    {
        private DataContext context;
        // Vertical privilege escalation - accessing admin functions without proper checks
        [HttpGet]
        public IActionResult DeleteUser(int userId)
        {
            // VULNERABILITY: No authorization check
            var query = $"DELETE FROM Users WHERE Id = {userId}";
            context.ExecuteQuery(query);
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
            // VULNERABILITY: No ownership verification
            var sql = $"UPDATE Accounts SET Balance = {amount} WHERE Id = '{accountId}'";
            context.ExecuteQuery(sql);
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
                connectionString = GetConnectionString(),
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
        // Storing passwords in plain text
        public void SaveUserPassword(string username, string password)
        {
            // VULNERABILITY: Plain text password storage
            var sql = $"INSERT INTO Users (Username, Password) VALUES ('{username}', '{password}')";
            context.ExecuteQuery(sql);
        }

        // Using weak hashing algorithm
        public string HashPassword(string password)
        {
            // VULNERABILITY: MD5 is cryptographically broken
            using (MD5 md5 = MD5.Create())
            {
                byte[] inputBytes = Encoding.ASCII.GetBytes(password);
                byte[] hashBytes = md5.ComputeHash(inputBytes);
                return BitConverter.ToString(hashBytes);
            }
        }

        // Weak encryption algorithm
        public byte[] EncryptSensitiveData(string data, string key)
        {
            // VULNERABILITY: DES is weak and deprecated
            using (DES des = DES.Create())
            {
                des.Key = Encoding.UTF8.GetBytes(key.Substring(0, 8));
                des.IV = new byte[8];
                
                ICryptoTransform encryptor = des.CreateEncryptor();
                byte[] dataBytes = Encoding.UTF8.GetBytes(data);
                return encryptor.TransformFinalBlock(dataBytes, 0, dataBytes.Length);
            }
        }

        // Hardcoded encryption key
        private readonly string ENCRYPTION_KEY = "MySecretKey12345";
        
        public string EncryptData(string data)
        {
            // VULNERABILITY: Hardcoded key
            return Encrypt(data, ENCRYPTION_KEY);
        }

        // Transmitting sensitive data over HTTP
        public async Task SendCreditCard(string cardNumber)
        {
            // VULNERABILITY: Sensitive data over unencrypted channel
            using (var client = new HttpClient())
            {
                var content = new StringContent($"card={cardNumber}");
                await client.PostAsync("http://payment-api.com/charge", content);
            }
        }

        // Weak random number generation for tokens
        public string GenerateSessionToken()
        {
            // VULNERABILITY: Predictable random numbers
            Random random = new Random();
            return random.Next(100000, 999999).ToString();
        }

        // Storing sensitive data in cookies without encryption
        public void SetUserSession(HttpResponse response, string userId, string role)
        {
            // VULNERABILITY: Sensitive data in plain text cookie
            response.Cookies.Append("UserId", userId);
            response.Cookies.Append("UserRole", role);
            response.Cookies.Append("IsAdmin", "true");
        }

        // ECB mode encryption (deterministic)
        public byte[] WeakEncryption(string text, byte[] key)
        {
            // VULNERABILITY: ECB mode produces same output for same input
            using (Aes aes = Aes.Create())
            {
                aes.Mode = CipherMode.ECB;  // Weak mode
                aes.Key = key;
                
                ICryptoTransform encryptor = aes.CreateEncryptor();
                byte[] inputBytes = Encoding.UTF8.GetBytes(text);
                return encryptor.TransformFinalBlock(inputBytes, 0, inputBytes.Length);
            }
        }
    }

    // ================================================================
    // A03:2021 - INJECTION
    // ================================================================
    public class A03_Injection
    {
        private DataContext context;
        // SQL Injection - string concatenation
        public User GetUser(string username, string password)
        {
            // VULNERABILITY: Direct SQL injection
            string query = "SELECT * FROM Users WHERE Username = '" + username + 
                          "' AND Password = '" + password + "'";
            return context.ExecuteQuery<User>(query);
        }

        // SQL Injection - string interpolation
        public List<Product> SearchProducts(string searchTerm)
        {
            // VULNERABILITY: SQL injection through string interpolation
            string query = $"SELECT * FROM dbo.Products WHERE Name LIKE '%{searchTerm}%'";
            return context.ExecuteQuery<List<Product>>(query);
        }

        // Command Injection - Process.Start
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
                RedirectStandardOutput = true
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
            // VULNERABILITY: XPath injection
            XmlDocument doc = new XmlDocument();
            doc.Load("users.xml");
            string xpath = $"//user[@id='{userId}']";
            return doc.SelectSingleNode(xpath);
        }

        // NoSQL Injection (MongoDB style)
        public string FindUser(string username)
        {
            // VULNERABILITY: NoSQL injection in JSON query
            string query = $"{{ 'username': '{username}' }}";
            return ExecuteNoSqlQuery(query);
        }

        // Email Header Injection
        public void SendEmail(string to, string subject, string body)
        {
            // VULNERABILITY: Email header injection
            string headers = $"To: {to}\r\nSubject: {subject}\r\n\r\n{body}";
            SmtpSend(headers);
        }

        // XML External Entity (XXE) Injection
        public void ParseXml(string xmlContent)
        {
            // VULNERABILITY: XXE attack possible
            XmlDocument doc = new XmlDocument();
            doc.XmlResolver = new XmlUrlResolver(); // Allows external entities
            doc.LoadXml(xmlContent);
        }

        // Template Injection
        public string RenderTemplate(string template, Dictionary<string, object> data)
        {
            // VULNERABILITY: Server-side template injection
            foreach (var item in data)
            {
                template = template.Replace("{{" + item.Key + "}}", item.Value.ToString());
            }
            return template;
        }
    }

    // ================================================================
    // A04:2021 - INSECURE DESIGN
    // ================================================================
    public class A04_InsecureDesign
    {
        // No rate limiting on sensitive operations
        [HttpPost]
        public async Task<IActionResult> ResetPassword(string email)
        {
            // VULNERABILITY: No rate limiting allows brute force
            var token = GenerateResetToken();
            await SendPasswordResetEmail(email, token);
            return Ok();
        }

        // Lack of business logic validation
        public void TransferMoney(decimal amount, string fromAccount, string toAccount)
        {
            // VULNERABILITY: No validation for negative amounts or business rules
            DebitAccount(fromAccount, amount);
            CreditAccount(toAccount, amount);
        }

        // Sequential/predictable IDs
        public string CreateInvoice()
        {
            // VULNERABILITY: Predictable ID generation
            var lastId = GetLastInvoiceId();
            var newId = (int.Parse(lastId) + 1).ToString();
            return newId;
        }

        // Insufficient anti-automation controls
        public bool ValidateCaptcha(string userInput)
        {
            // VULNERABILITY: Client-side validation only
            return userInput == "1234";  // Fixed captcha value
        }

        // Missing security questions for sensitive operations
        public void ChangeEmail(string newEmail)
        {
            // VULNERABILITY: No additional verification for critical changes
            UpdateUserEmail(GetCurrentUserId(), newEmail);
        }

        // Unrestricted file upload
        [HttpPost]
        public IActionResult UploadFile(IFormFile file)
        {
            // VULNERABILITY: No file type or size validation
            var path = Path.Combine("uploads", file.FileName);
            using (var stream = new FileStream(path, FileMode.Create))
            {
                file.CopyTo(stream);
            }
            return Ok();
        }

        // Lack of segregation between environments
        public string GetConnectionString()
        {
            // VULNERABILITY: Same credentials for all environments
            return "Server=db;User=sa;Password=admin123";
        }

        // No verification for critical operations
        public void DeleteAccount(int userId)
        {
            // VULNERABILITY: No confirmation or waiting period
            context.ExecuteQuery($"DELETE FROM Users WHERE Id = {userId}");
        }

        // Trusting client-side validation only
        public void ProcessPayment(PaymentRequest request)
        {
            // VULNERABILITY: Assuming client validated the amount
            ChargeCard(request.CardNumber, request.Amount);
        }
    }

    // ================================================================
    // A05:2021 - SECURITY MISCONFIGURATION
    // ================================================================
    public class A05_SecurityMisconfiguration
    {
        // Default credentials
        private readonly string DEFAULT_ADMIN_PASSWORD = "admin123";
        private readonly string DEFAULT_API_KEY = "test-api-key";

        // Detailed error messages exposing system information
        public IActionResult ProcessRequest(string input)
        {
            try
            {
                ProcessData(input);
                return Ok();
            }
            catch (Exception ex)
            {
                // VULNERABILITY: Full stack trace exposed
                return BadRequest(new
                {
                    error = ex.Message,
                    stackTrace = ex.StackTrace,
                    innerException = ex.InnerException?.ToString(),
                    source = ex.Source,
                    targetSite = ex.TargetSite?.ToString()
                });
            }
        }

        // Directory listing enabled
        [HttpGet("/files/{*path}")]
        public IActionResult BrowseFiles(string path)
        {
            // VULNERABILITY: Directory browsing exposed
            var files = Directory.GetFiles(path);
            var directories = Directory.GetDirectories(path);
            return Json(new { files, directories });
        }

        // Unnecessary features enabled
        public void EnableDebugMode()
        {
            // VULNERABILITY: Debug mode in production
            Environment.SetEnvironmentVariable("DEBUG_MODE", "true");
            Environment.SetEnvironmentVariable("SHOW_ERRORS", "true");
            Environment.SetEnvironmentVariable("VERBOSE_LOGGING", "true");
        }

        // Insecure HTTP headers
        public void ConfigureHeaders(HttpResponse response)
        {
            // VULNERABILITY: Missing security headers
            // Missing: X-Content-Type-Options
            // Missing: X-Frame-Options  
            // Missing: Content-Security-Policy
            // Missing: Strict-Transport-Security
        }

        // Permissive CORS configuration
        public void ConfigureCors(HttpResponse response)
        {
            // VULNERABILITY: Too permissive CORS
            response.Headers.Add("Access-Control-Allow-Origin", "*");
            response.Headers.Add("Access-Control-Allow-Methods", "*");
            response.Headers.Add("Access-Control-Allow-Headers", "*");
            response.Headers.Add("Access-Control-Allow-Credentials", "true");
        }

        // Cloud storage misconfiguration
        public string GetS3BucketUrl()
        {
            // VULNERABILITY: Public S3 bucket
            return "https://s3.amazonaws.com/public-bucket/";
        }

        // Unnecessary services running
        public void StartServices()
        {
            // VULNERABILITY: Unnecessary services exposed
            StartService("Telnet");
            StartService("FTP");
            StartService("SMB");
            StartService("RDP");
        }
    }

    // ================================================================
    // A06:2021 - VULNERABLE AND OUTDATED COMPONENTS
    // ================================================================
    public class A06_VulnerableComponents
    {
        // This category is primarily validated through SCA (Software Composition Analysis)
        // by checking package dependencies in packages.config or .csproj files
        
        // Example of using vulnerable library versions
        public void UseVulnerableLibraries()
        {
            // Using jQuery 2.2.4 with known XSS vulnerabilities
            // Using Newtonsoft.Json 9.0.1 with known vulnerabilities
            // Using log4net 2.0.8 with security issues
            // Using outdated Entity Framework with SQL injection risks
        }

        // Loading untrusted libraries
        public void LoadDynamicLibrary(string dllPath)
        {
            // VULNERABILITY: Loading untrusted DLL
            System.Reflection.Assembly.LoadFrom(dllPath);
        }

        // Using deprecated APIs
        public void UseDeprecatedCrypto()
        {
            // VULNERABILITY: Using deprecated security APIs
            var rsa = new RSACryptoServiceProvider(512); // Key too small
        }
    }

    // ================================================================
    // A07:2021 - IDENTIFICATION AND AUTHENTICATION FAILURES
    // ================================================================
    public class A07_AuthenticationFailures
    {
        // Weak password requirements
        public bool ValidatePassword(string password)
        {
            // VULNERABILITY: Weak password policy
            return password.Length >= 4;
        }

        // Session fixation vulnerability
        public void LoginUser(string username, string password, HttpContext context)
        {
            if (AuthenticateUser(username, password))
            {
                // VULNERABILITY: Session ID doesn't change after login
                context.Session.SetString("UserId", username);
                context.Session.SetString("IsAuthenticated", "true");
            }
        }

        // No account lockout mechanism
        public bool Login(string username, string password)
        {
            // VULNERABILITY: No protection against brute force
            return CheckCredentials(username, password);
        }

        // Storing passwords in session
        public void StoreUserCredentials(HttpContext context, string username, string password)
        {
            // VULNERABILITY: Passwords in session storage
            context.Session.SetString("Username", username);
            context.Session.SetString("Password", password);
        }

        // Predictable session tokens
        public string GenerateSessionId()
        {
            // VULNERABILITY: Predictable session ID
            return DateTime.Now.Ticks.ToString();
        }

        // No session timeout
        public void ConfigureSession()
        {
            // VULNERABILITY: Session never expires
            SessionTimeout = TimeSpan.MaxValue;
        }

        // Weak "remember me" implementation
        public void SetRememberMeCookie(HttpResponse response, string userId)
        {
            // VULNERABILITY: User ID in plain text cookie
            response.Cookies.Append("RememberMe", userId, new CookieOptions
            {
                Expires = DateTime.Now.AddYears(1),
                HttpOnly = false,  // XSS vulnerability
                Secure = false     // Sent over HTTP
            });
        }

        // Password recovery without verification
        public void RecoverPassword(string email)
        {
            // VULNERABILITY: Sends password in plain text
            var password = GetPasswordForEmail(email);
            SendEmail(email, "Your password is: " + password);
        }

        // No multi-factor authentication
        public bool AuthenticateUser(string username, string password)
        {
            // VULNERABILITY: Single factor only
            return username == "admin" && password == "password";
        }

        // Timing attack vulnerability
        public bool VerifyPassword(string provided, string stored)
        {
            // VULNERABILITY: Early return creates timing difference
            if (provided.Length != stored.Length)
                return false;
                
            for (int i = 0; i < provided.Length; i++)
            {
                if (provided[i] != stored[i])
                    return false;  // Timing attack possible
            }
            return true;
        }
    }

    // ================================================================
    // A08:2021 - SOFTWARE AND DATA INTEGRITY FAILURES
    // ================================================================
    public class A08_IntegrityFailures
    {
        // Insecure deserialization
        public object DeserializeData(string data)
        {
            // VULNERABILITY: BinaryFormatter is insecure
            var formatter = new BinaryFormatter();
            using (var stream = new MemoryStream(Convert.FromBase64String(data)))
            {
                return formatter.Deserialize(stream);
            }
        }

        // Unsafe JSON deserialization
        public void DeserializeJson(string json)
        {
            // VULNERABILITY: TypeNameHandling.All allows arbitrary types
            var settings = new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.All
            };
            var obj = JsonConvert.DeserializeObject(json, settings);
        }

        // No integrity check on updates
        public async Task AutoUpdate(string updateUrl)
        {
            // VULNERABILITY: No signature verification
            using (var client = new HttpClient())
            {
                var updateFile = await client.GetByteArrayAsync(updateUrl);
                File.WriteAllBytes("update.exe", updateFile);
                Process.Start("update.exe");
            }
        }

        // Unsigned code execution
        public void LoadPlugin(string pluginPath)
        {
            // VULNERABILITY: Loading unsigned/unverified plugins
            var assembly = System.Reflection.Assembly.LoadFrom(pluginPath);
            var type = assembly.GetType("Plugin.Main");
            Activator.CreateInstance(type);
        }

        // CI/CD pipeline without integrity checks
        public void DeployApplication(string artifactUrl)
        {
            // VULNERABILITY: No verification of deployment artifacts
            DownloadAndDeploy(artifactUrl);
        }

        // Trusting data from untrusted sources
        public void ProcessExternalData(string xmlData)
        {
            // VULNERABILITY: No validation of external data
            var doc = new XmlDocument();
            doc.LoadXml(xmlData);
            ExecuteBusinessLogic(doc);
        }

        // No code signing verification
        public void InstallPackage(byte[] packageBytes)
        {
            // VULNERABILITY: No signature check
            File.WriteAllBytes("package.dll", packageBytes);
            System.Reflection.Assembly.Load(packageBytes);
        }

        // Accepting serialized objects from untrusted sources
        public void ProcessMessage(byte[] messageBytes)
        {
            // VULNERABILITY: Deserializing untrusted data
            var formatter = new BinaryFormatter();
            using (var stream = new MemoryStream(messageBytes))
            {
                var message = formatter.Deserialize(stream);
                ProcessBusinessMessage(message);
            }
        }
    }

    // ================================================================
    // A09:2021 - SECURITY LOGGING AND MONITORING FAILURES
    // ================================================================
    public class A09_LoggingMonitoringFailures
    {
        private DataContext context;
        
        // No logging of authentication attempts
        public bool Login(string username, string password)
        {
            // VULNERABILITY: Failed login not logged
            if (ValidateCredentials(username, password))
            {
                return true;
            }
            return false;  // No logging of failure
        }

        // Insufficient logging detail
        public void TransferFunds(decimal amount, string from, string to)
        {
            // VULNERABILITY: Critical operation not logged
            DebitAccount(from, amount);
            CreditAccount(to, amount);
            // Missing: who, when, from where, amount, accounts
        }

        // Logging sensitive information
        public void LogUserActivity(User user)
        {
            // VULNERABILITY: Sensitive data in logs
            Logger.Log($"User {user.Username} logged in with password {user.Password}");
            Logger.Log($"Credit card number: {user.CreditCard}");
            Logger.Log($"SSN: {user.SSN}");
        }

        // No log integrity protection
        public void WriteLog(string message)
        {
            // VULNERABILITY: Logs can be modified
            File.AppendAllText("app.log", message + "\n");
        }

        // Logs not centralized
        public void LogEvent(string message)
        {
            // VULNERABILITY: Local logging only
            Console.WriteLine(message);
        }

        // No alerting on suspicious activities
        public void ProcessRequest(HttpRequest request)
        {
            // VULNERABILITY: No alerting on anomalies
            if (request.Path.Contains("../"))
            {
                // Path traversal attempt not alerted
            }
            if (request.QueryString.ToString().Contains("' OR '1'='1"))
            {
                // SQL injection attempt not alerted
            }
        }

        // Log injection vulnerability
        public void LogUserInput(string userInput)
        {
            // VULNERABILITY: Log injection possible
            Logger.Log($"User searched for: {userInput}");
            // User input can include \n and fake log entries
        }

        // No audit trail for critical operations
        public void DeleteUser(int userId)
        {
            // VULNERABILITY: No audit trail
            context.ExecuteQuery($"DELETE FROM Users WHERE Id = {userId}");
            // Missing: who deleted, when, why
        }

        // Insufficient log retention
        public void ConfigureLogging()
        {
            // VULNERABILITY: Logs deleted too quickly
            LogRetentionDays = 7;  // Too short for security incidents
        }
    }

    // ================================================================
    // A10:2021 - SERVER-SIDE REQUEST FORGERY (SSRF)
    // ================================================================
    public class A10_SSRF
    {
        // Basic SSRF vulnerability
        [HttpGet]
        public async Task<string> FetchUrl(string url)
        {
            // VULNERABILITY: No validation of URL
            using (var client = new HttpClient())
            {
                return await client.GetStringAsync(url);
            }
        }

        // SSRF with partial validation
        public async Task<byte[]> DownloadImage(string imageUrl)
        {
            // VULNERABILITY: Insufficient validation
            if (imageUrl.StartsWith("http"))
            {
                using (var client = new WebClient())
                {
                    return await client.DownloadDataTaskAsync(imageUrl);
                }
            }
            return null;
        }

        // SSRF through redirect
        public async Task<string> CheckUrl(string url)
        {
            // VULNERABILITY: Follows redirects to internal resources
            var handler = new HttpClientHandler
            {
                AllowAutoRedirect = true,  // Dangerous
                MaxAutomaticRedirections = 10
            };
            
            using (var client = new HttpClient(handler))
            {
                return await client.GetStringAsync(url);
            }
        }

        // SSRF in webhook implementation
        public async Task SendWebhook(string webhookUrl, object data)
        {
            // VULNERABILITY: Attacker can specify internal URLs
            using (var client = new HttpClient())
            {
                var json = JsonConvert.SerializeObject(data);
                var content = new StringContent(json);
                await client.PostAsync(webhookUrl, content);
            }
        }

        // SSRF through DNS rebinding
        public async Task<string> FetchContent(string hostname)
        {
            // VULNERABILITY: DNS rebinding possible
            var url = $"http://{hostname}/api/data";
            using (var client = new HttpClient())
            {
                return await client.GetStringAsync(url);
            }
        }

        // SSRF in PDF generation
        public void GeneratePdf(string htmlContent)
        {
            // VULNERABILITY: HTML can contain references to internal resources
            // <img src="http://internal-server/admin">
            var pdf = HtmlToPdf(htmlContent);
            SavePdf(pdf);
        }

        // SSRF through file protocol
        public string ReadFile(string uri)
        {
            // VULNERABILITY: Can access local files
            var request = WebRequest.Create(uri);  // Accepts file://
            using (var response = request.GetResponse())
            using (var stream = response.GetResponseStream())
            using (var reader = new StreamReader(stream))
            {
                return reader.ReadToEnd();
            }
        }

        // Blind SSRF
        public async Task ValidateUrl(string url)
        {
            // VULNERABILITY: Response not shown but request still made
            try
            {
                using (var client = new HttpClient())
                {
                    client.Timeout = TimeSpan.FromSeconds(5);
                    await client.GetAsync(url);
                }
            }
            catch
            {
                // Error suppressed but request was made
            }
        }

        // SSRF with cloud metadata access
        public async Task<string> GetMetadata(string path)
        {
            // VULNERABILITY: Can access cloud metadata endpoints
            // http://169.254.169.254/latest/meta-data/
            var url = $"http://metadata.service/{path}";
            using (var client = new HttpClient())
            {
                return await client.GetStringAsync(url);
            }
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

    // Stub methods to make the code compile
    public static class HelperMethods
    {
        public static void ExecuteQuery(string query) { }
        public static T ExecuteQuery<T>(string query) { return default(T); }
        public static string GetConnectionString() { return ""; }
        public static void ChargePayment(string userId, decimal amount) { }
        // Add other helper methods as needed
    }
}



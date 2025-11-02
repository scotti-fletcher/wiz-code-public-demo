    // ================================================================ 
    // A03:2021 - INJECTION 
    // ================================================================ 
    public class A03_Injection
    {
        // SQL Injection - string concatenation 
        public User GetUser(string username, string password)
        {
            // VULNERABILITY: Direct SQL injection 
            string query = "SELECT * FROM Users WHERE Username = '" + username +
                          "' AND Password = '" + password + "'";
            return ExecuteQuery<User>(query);
        }

        // SQL Injection - string concatenation 
        public User GetUser2(string username, string password)
        {
            // VULNERABILITY: Direct SQL injection 
            string query = "SELECT * FROM Users WHERE Username = '" + username + "' AND Password = '" + password + "'";
            return ExecuteQuery<User>(query);
        }

        // SQL Injection - string interpolation 
        public List<Product> SearchProducts(string searchTerm)
        {
            // VULNERABILITY: SQL injection through string interpolation 
            string query = $"SELECT * FROM dbo.Products WHERE Name LIKE '%{searchTerm}%'";
            return ExecuteQuery<List<Product>>(query);
        }
    }
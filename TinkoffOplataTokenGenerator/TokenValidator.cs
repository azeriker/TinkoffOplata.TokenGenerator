using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json.Linq;

namespace TinkoffOplata.TokenValidator
{
    public sealed class TokenValidator
    {
        private const string PASSWORD_KEY = "Password";
        private const string TOKEN_KEY = "Token";

        private readonly string _passwordValue;
        private readonly IReadOnlyList<string> _keysToExclude = new[] { "Receipt", "Data", TOKEN_KEY };

        public TokenValidator(string passwordValue)
        {
            if (string.IsNullOrEmpty(passwordValue))
                throw new ArgumentNullException(nameof(passwordValue));

            _passwordValue = passwordValue;
        }

        public bool Validate(JToken requestBody)
        {
            var keyAndValues = ConvertToTuplesList(requestBody);

            var token = keyAndValues.FirstOrDefault(kv => kv.Key == TOKEN_KEY).Value;

            ClearList(keyAndValues);

            keyAndValues.Add((PASSWORD_KEY, _passwordValue));

            keyAndValues = keyAndValues.OrderBy(kv => kv.Key).ToList();

            var concatedValues = ConcatAllValues(keyAndValues);

            var hashedValues = CalculateSHA256Hash(concatedValues);

            return hashedValues == token;
        }

        private List<(string Key, string Value)> ConvertToTuplesList(JToken jtoken)
        {
            return jtoken.Select(kv =>
            {
                var jp = kv as JProperty;
                return (jp?.Name, Value: jp?.Value.ToString());
            }).ToList();
        }

        private void ClearList(List<(string Key, string Value)> list)
        {
            list.RemoveAll(kv => _keysToExclude.Contains(kv.Key));
        }

        private string ConcatAllValues(List<(string Key, string Value)> list)
        {
            var resultString = string.Empty;
            list.ForEach(kv => resultString += kv.Value);
            return resultString;
        }

        private string CalculateSHA256Hash(string str)
        {
            using (var sha256 = SHA256.Create())
            {

                var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(str));
                var hashedStr = Encoding.UTF8.GetString(hash);

                return hashedStr;
            }
        }

    }
}

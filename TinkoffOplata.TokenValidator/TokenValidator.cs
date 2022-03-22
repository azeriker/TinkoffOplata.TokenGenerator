using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json.Linq;

namespace TinkoffOplata
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

        public string CalculateToken(JToken request)
        {
            var keyAndValues = ConvertToTuplesList(request);

            ClearList(keyAndValues);

            keyAndValues.Add((PASSWORD_KEY, _passwordValue));

            keyAndValues = keyAndValues.OrderBy(kv => kv.Key).ToList();

            var concatenatedValues = ConcatAllValues(keyAndValues);

            return CalculateSHA256Hash(concatenatedValues).ToLowerInvariant();
        }

        public bool Validate(JToken requestBody)
        {
            var keyAndValues = ConvertToTuplesList(requestBody);

            var token = keyAndValues.FirstOrDefault(kv => kv.Key == TOKEN_KEY).Value;

            var hashedValues = CalculateToken(requestBody);

            return token.Equals(hashedValues, StringComparison.OrdinalIgnoreCase);
        }

        private List<(string Key, string Value)> ConvertToTuplesList(JToken jtoken)
        {
            return jtoken.Select(kv =>
            {
                var jp = kv as JProperty;
                var name = jp.Name;
                var value = jp.Value.Type == JTokenType.Boolean ? jp.Value.ToString().ToLower() : jp.Value.ToString();
                return (name, value);
            }).ToList();
        }

        private void ClearList(List<(string Key, string Value)> list)
        {
            list.RemoveAll(kv => _keysToExclude.Any(k => k.Equals(kv.Key, StringComparison.InvariantCultureIgnoreCase)));
        }

        private string ConcatAllValues(List<(string Key, string Value)> list)
        {
            return string.Concat(list.Select(kv => kv.Value));
        }

        private string CalculateSHA256Hash(string str)
        {
            using (var sha256 = SHA256.Create())
            {

                var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(str));
                var hashedStr = string.Concat(hash.Select(b => b.ToString("X2")).ToArray());

                return hashedStr;
            }
        }

    }
}

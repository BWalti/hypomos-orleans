namespace Webapp.Helpers
{
    using System.Collections.Generic;
    using System.Linq;
    using Microsoft.AspNetCore.Identity;
    using Webapp.Models;

    public static class IdentityResultExtensions
    {
        public static ApiResult AsApiResult(this IdentityResult identityResult)
        {
            var result = new ApiResult();
            foreach (var error in identityResult.Errors)
            {
                result.Errors.Add(string.Empty, new List<string> {error.Description});
            }

            result.Message = $"{identityResult.Errors.Count()} error(s) in account operation";
            return result;
        }

        public static ApiModel<TValue> AsApiModel<TValue>(this IdentityResult identityResult, TValue val)
            where TValue : class
        {
            return new ApiModel<TValue>(val, identityResult.AsApiResult());
        }
    }
}
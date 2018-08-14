namespace Webapp.Models
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using Newtonsoft.Json;

    [JsonObject]
    public class ApiResult
    {
        public static ApiResult SuccessResult = AsSuccess();

        public ApiResult(string errorField, string errorMessage) : this()
        {
            this.Errors.Add(errorField, new List<string>(new[] {errorMessage}));
        }

        public ApiResult(int errorCode, string errorMessage) : this()
        {
            this.Code = this.Code;
            this.Message = errorMessage;
            this.Errors.Add("", new List<string>(new[] {errorMessage}));
        }

        public ApiResult()
        {
            this.Errors = new Dictionary<string, List<string>>();
            this.Code = 0;
        }

        public ApiResult(Dictionary<string, List<string>> errors)
        {
            this.Errors = errors;
            this.Code = 0;
        }

        public string Status => this.Errors.Keys.Any() ? "Error" : "OK";

        public bool Success => !this.Errors.Keys.Any();

        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore)]
        public string Message { get; set; }

        /// <summary>
        ///     Dictionary key is the field having the error
        ///     Value is a list of errors. We don't support errors caused by a combination of fields like the Nancy ModelResult
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore)]
        public Dictionary<string, List<string>> Errors { get; set; }

        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore)]
        public int Code { get; set; }

        // Helper methods
        public static ApiResult AsError(string errorField, string errorMessage)
        {
            return new ApiResult(errorField, errorMessage);
        }

        public static ApiResult AsError(string errorMessage, int errorCode = 0)
        {
            return new ApiResult(errorCode, errorMessage);
        }

        public static ApiResult AsSuccess(string message = null)
        {
            return new ApiResult {Message = message};
        }

        public static ApiResult FromException(Exception exception, bool includeExceptions = false)
        {
            ApiResult result;
            if (includeExceptions)
            {
                result = new ApiResult {Message = "Exception(s) occurred"};
                result.Errors.Add("Exceptions", new List<string>(new[] {exception.Message}));
            }
            else
            {
                result = AsError("Server Error");
            }

            return result;
        }
    }
}
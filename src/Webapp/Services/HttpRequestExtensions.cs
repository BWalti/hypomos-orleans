﻿namespace Webapp.Services
{
    using System.Net;
    using Microsoft.AspNetCore.Http;

    public static class HttpRequestExtensions
    {
        public static bool IsLocal(this HttpRequest req)
        {
            var connection = req.HttpContext.Connection;
            if (connection.RemoteIpAddress != null)
            {
                if (connection.LocalIpAddress != null)
                {
                    return connection.RemoteIpAddress.Equals(connection.LocalIpAddress);
                }

                return IPAddress.IsLoopback(connection.RemoteIpAddress);
            }

            // for in memory TestServer or when dealing with default connection info
            if ((connection.RemoteIpAddress == null) && (connection.LocalIpAddress == null))
            {
                return true;
            }

            return false;
        }
    }
}
namespace Webapp.Identity
{
    using System;
    using System.Collections.Generic;
    using GrainInterfaces;

    public class ApplicationUser
    {
        public ApplicationUser()
        {
        }

        public ApplicationUser(string userId, IdentityState identityData)
        {
            this.UserId = userId;
            this.UserName = identityData.UserName;
            this.NormalizedUserName = identityData.NormalizedUserName;
            this.Email = identityData.Email;
            this.NormalizedEmail = identityData.NormalizedEmail;
            this.EmailConfirmed = identityData.EmailConfirmed;
            this.PhoneNumber = identityData.PhoneNumber;
            this.PhoneNumberConfirmed = identityData.PhoneNumberConfirmed;
            this.PasswordHash = identityData.PasswordHash;
            this.SecurityStamp = identityData.SecurityStamp;
            this.Registered = identityData.Registered;
            this.LockoutEnabled = identityData.LockoutEnabled;
            this.LockoutEnd = identityData.LockoutEnd;
            this.AccessFailedCount = identityData.AccessFailedCount;
            this.TwoFactorEnabled = identityData.TwoFactorEnabled;
            this.Roles = identityData.Roles;
            this.ExternalLogins = identityData.ExternalLogins;
            this.AuthenticationTokens = identityData.AuthenticationTokens;
            this.ConcurrencyStamp = identityData.ConcurrencyStamp;
        }

        public string UserId { get; set; }
        public string UserName { get; set; }
        public string NormalizedUserName { get; set; }
        public string Email { get; set; }
        public string NormalizedEmail { get; set; }
        public bool EmailConfirmed { get; set; }
        public string PhoneNumber { get; set; }
        public bool PhoneNumberConfirmed { get; set; }
        public string PasswordHash { get; set; }
        public string SecurityStamp { get; set; }
        public DateTimeOffset? Registered { get; set; }
        public bool LockoutEnabled { get; set; }
        public DateTimeOffset? LockoutEnd { get; set; }
        public int AccessFailedCount { get; set; }
        public bool TwoFactorEnabled { get; set; }
        public int InvitesAvailable { get; set; }
        public List<string> Roles { get; set; } = new List<string>();
        public List<ExternalLoginState> ExternalLogins { get; set; } = new List<ExternalLoginState>();
        public List<AuthTokenState> AuthenticationTokens { get; set; } = new List<AuthTokenState>();
        public string ConcurrencyStamp { get; set; }
        public PersonalState PersonalData { get; set; }

        public override string ToString()
        {
            return this.UserId;
        }
    }

    public class ApplicationUserLogin
    {
        public string LoginProvider { get; set; }
        public string ProviderDisplayName { get; set; }
        public string ProviderKey { get; set; }
        public string UserId { get; set; }
    }

    public class ApplicationToken
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string LoginProvider { get; set; }
    }

    public class UserRole
    {
        public string Role { get; set; }
    }
}
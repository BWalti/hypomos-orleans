namespace Webapp.Identity
{
    using System;
    using System.Collections.Generic;
    using System.Security.Claims;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.Extensions.Logging;
    using Microsoft.Extensions.Options;

    public class ApplicationUserManager : UserManager<ApplicationUser>
    {
        public ApplicationUserManager(
            IUserStore<ApplicationUser> store,
            IOptions<IdentityOptions> options,
            IPasswordHasher<ApplicationUser> hasher,
            IEnumerable<IUserValidator<ApplicationUser>> userValidators,
            IEnumerable<IPasswordValidator<ApplicationUser>> passwordValidators,
            ILookupNormalizer keyNormalizer,
            IdentityErrorDescriber errors,
            IServiceProvider services,
            ILogger<UserManager<ApplicationUser>> logger) : base(store, options, hasher, userValidators,
            passwordValidators, keyNormalizer, errors, services, logger)
        {
        }

        public override bool SupportsQueryableUsers => false;
        public override bool SupportsUserClaim => false;

        public override Task<IList<Claim>> GetClaimsAsync(ApplicationUser user)
        {
            return base.GetClaimsAsync(user);
        }
    }
}
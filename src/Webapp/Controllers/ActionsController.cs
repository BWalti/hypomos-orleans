namespace Webapp.Controllers
{
    using System;
    using System.Threading.Tasks;
    using GrainInterfaces;
    using Microsoft.AspNetCore.Hosting;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Mvc;
    using Orleans;
    using Webapp.Models;
    using Webapp.Services;

    public class ActionsController : Controller
    {
        private readonly IHostingEnvironment env;
        private readonly IClusterClient grainClient;
        private readonly Guid sessionId;

        public ActionsController(IClusterClient grainClient, IHttpContextAccessor httpContextAccessor,
            IHostingEnvironment env)
        {
            this.grainClient = grainClient;
            this.env = env;
            var sessionCookie = httpContextAccessor.HttpContext.Request.Cookies["SESSION"];
            if (string.IsNullOrEmpty(sessionCookie) || !Guid.TryParse(sessionCookie, out this.sessionId))
            {
                this.sessionId = Guid.NewGuid();
                httpContextAccessor.HttpContext.Response.Cookies.Append("SESSION", this.sessionId.ToString(),
                    new CookieOptions
                    {
                        Expires = DateTimeOffset.UtcNow + TimeSpan.FromDays(365),
                        HttpOnly = false,
                        Secure = httpContextAccessor.HttpContext.Request.IsHttps
                    });
            }
        }

        [HttpGet("~/counterstate")]
        public async Task<IActionResult> CounterState(Guid id)
        {
            var grain = this.grainClient.GetGrain<ICounterGrain>(id);
            try
            {
                var state = await grain.GetState() ?? new CounterState();
                return this.Ok(state);
            }
            catch (Exception e)
            {
                return this.StatusCode(500, ApiResult.FromException(e, this.env.IsDevelopment()));
            }
        }

        // This is another, more generic, way to send actions from the client to the server
        // This is unused; the pattern is more clear when commands directly call the API
        [HttpPost("~/action")]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Action([FromBody] dynamic actionData)
        {
            var action = ActionHelper.ConstructTypedAction(actionData);
            if (action != null)
            {
                // We can send the action directly, or send it via a stream
                var grain = this.grainClient.GetGrain<ICounterGrain>(this.sessionId);
                await grain.Process(action);
                return this.Ok();
            }

            return this.BadRequest(ApiModel.AsError("invalid action"));
        }

        [HttpPost("~/startcounter")]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> StartCounter()
        {
            var grain = this.grainClient.GetGrain<ICounterGrain>(this.sessionId);
            try
            {
                await grain.StartCounterTimer();
                return this.Ok();
            }
            catch (Exception e)
            {
                return this.StatusCode(500, ApiResult.FromException(e, this.env.IsDevelopment()));
            }
        }

        [HttpPost("~/stopcounter")]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> StopCounter()
        {
            var grain = this.grainClient.GetGrain<ICounterGrain>(this.sessionId);
            try
            {
                await grain.StopCounterTimer();
                return this.Ok();
            }
            catch (Exception e)
            {
                return this.StatusCode(500, ApiResult.FromException(e, this.env.IsDevelopment()));
            }
        }

        [HttpPost("~/incrementcounter")]
        public async Task<ActionResult> IncrementCounter()
        {
            var grain = this.grainClient.GetGrain<ICounterGrain>(this.sessionId);
            try
            {
                await grain.IncrementCounter();
                return this.Ok();
            }
            catch (Exception e)
            {
                return this.StatusCode(500, ApiResult.FromException(e, this.env.IsDevelopment()));
            }
        }

        [HttpPost("~/decrementcounter")]
        public async Task<ActionResult> DecrementCounter()
        {
            var grain = this.grainClient.GetGrain<ICounterGrain>(this.sessionId);
            try
            {
                await grain.DecrementCounter();
                return this.Ok();
            }
            catch (Exception e)
            {
                return this.StatusCode(500, ApiResult.FromException(e, this.env.IsDevelopment()));
            }
        }
    }
}
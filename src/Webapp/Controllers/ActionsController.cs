using GrainInterfaces;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Orleans;
using System;
using System.Threading.Tasks;
using Webapp.Services;
using Microsoft.AspNetCore.Hosting;
using Webapp.Models;

namespace Webapp.Controllers
{
    public class ActionsController : Controller
    {
        private readonly Guid sessionId;
        private readonly IClusterClient grainClient;
        private readonly IHostingEnvironment env;

        public ActionsController(IClusterClient grainClient, IHttpContextAccessor httpContextAccessor, IHostingEnvironment env): base()
        {
            this.grainClient = grainClient;
            this.env = env;
            string sessionCookie = httpContextAccessor.HttpContext.Request.Cookies["SESSION"];
            if (string.IsNullOrEmpty(sessionCookie) || !Guid.TryParse(sessionCookie, out this.sessionId))
            {
                this.sessionId = Guid.NewGuid();
                httpContextAccessor.HttpContext.Response.Cookies.Append("SESSION", this.sessionId.ToString(), new CookieOptions { Expires = DateTimeOffset.UtcNow + TimeSpan.FromDays(365), HttpOnly = false, Secure = httpContextAccessor.HttpContext.Request.IsHttps });
            }
        }

        [HttpGet("~/counterstate")]
        public async Task<IActionResult> CounterState(Guid id)
        {
            var grain = this.grainClient.GetGrain<ICounterGrain>(id);
            try 
            {
                var state = (await grain.GetState()) ?? new CounterState();
                return Ok(state);
            }
            catch (Exception e)
            {
                return StatusCode(500, ApiResult.FromException(e, env.IsDevelopment()));
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
                return Ok();
            }
            else
            {
                return BadRequest(ApiModel.AsError("invalid action"));
            }
        }

        [HttpPost("~/startcounter")]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> StartCounter()
        {
            var grain = this.grainClient.GetGrain<ICounterGrain>(this.sessionId);
            try 
            {
                await grain.StartCounterTimer();
                return Ok();
            }
            catch (Exception e)
            {
                return StatusCode(500, ApiResult.FromException(e, env.IsDevelopment()));
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
                return Ok();
            }
            catch (Exception e)
            {
                return StatusCode(500, ApiResult.FromException(e, env.IsDevelopment()));
            }
        }

        [HttpPost("~/incrementcounter")]
        public async Task<ActionResult> IncrementCounter()
        {
            var grain = this.grainClient.GetGrain<ICounterGrain>(this.sessionId);
            try
            {
                await grain.IncrementCounter();
                return Ok();
            }
            catch (Exception e)
            {
                return StatusCode(500, ApiResult.FromException(e, env.IsDevelopment()));
            }
            
        }

        [HttpPost("~/decrementcounter")]
        public async Task<ActionResult> DecrementCounter()
        {
            var grain = this.grainClient.GetGrain<ICounterGrain>(this.sessionId);
            try
            {
                await grain.DecrementCounter();
                return Ok();
            }
            catch (Exception e)
            {
                return StatusCode(500, ApiResult.FromException(e, env.IsDevelopment()));
            }
        }
    }
}
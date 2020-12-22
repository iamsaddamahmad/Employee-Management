using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using EmployeeManagement.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using EmployeeManagement.Security;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.Facebook;

namespace EmployeeManagement
{
    public class Startup
    {
        private IConfiguration _config;

        public Startup(IConfiguration config)
        {
            _config = config;
        }
        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDbContextPool<AppDbContext>(
                options => options.UseSqlServer(_config.GetConnectionString("EmployeeDBConnection")));

            services.AddIdentity<ApplicationUser, IdentityRole>(options =>
            {
                options.Password.RequiredLength = 10;
                options.Password.RequiredUniqueChars = 3;
                options.SignIn.RequireConfirmedEmail = true;

                options.Tokens.EmailConfirmationTokenProvider = "CustomEmailConfirmation";

                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);

            }).AddEntityFrameworkStores<AppDbContext>()
            .AddDefaultTokenProviders()
            .AddTokenProvider<CustomEmailConfirmationTokenProvider
            <ApplicationUser>>("CustomEmailConfirmation");

            services.Configure<DataProtectionTokenProviderOptions>(o =>
                              o.TokenLifespan = TimeSpan.FromHours(5));

            services.Configure<CustomEmailConfirmationTokenProviderOptions>(o =>
            o.TokenLifespan = TimeSpan.FromDays(3));

            services.AddMvc(options => options.EnableEndpointRouting = false);
            services.AddMvc(options => {
                var policy = new AuthorizationPolicyBuilder()
                                .RequireAuthenticatedUser()
                                .Build();
                options.Filters.Add(new AuthorizeFilter(policy));
            }).AddXmlSerializerFormatters();

            services.AddAuthentication().
                 AddGoogle(options =>
                 {
                     
                     //options.CallbackPath = "";
                 })
                 .AddFacebook(options =>
                 {
                     
                 });



            services.ConfigureApplicationCookie(options =>
            {
                options.AccessDeniedPath = new PathString("/Administration/AccessDenied");
            });

            services.AddAuthorization(options =>
            {
                options.AddPolicy("DeleteRolePolicy",
                    policy => policy.RequireClaim("Delete Role"));

                //options.AddPolicy("EditRolePolicy", policy =>
                //policy.RequireAssertion(context => AuthorizeAccess(context)));
                //});

                //private bool AuthorizeAccess(AuthorizationHandlerContext context)
                //{
                //return context.User.IsInRole("Admin") &&
                //        context.User.HasClaim(claim => claim.Type == "Edit Role" && claim.Value == "true") ||
                //        context.User.IsInRole("Super Admin");


                options.AddPolicy("EditRolePolicy",
                 policy => policy.AddRequirements(new ManageAdminRolesAndClaimsRequirement()));

                options.AddPolicy("AdminRolePolicy",
                    policy => policy.RequireRole("Admin"));
            });

            services.AddScoped<IEmployeeRepository, SQLEmployeeRepository>();

            services.AddSingleton<IAuthorizationHandler, CanEditOnlyOtherAdminRolesAndClaimsHandler>();

            services.AddSingleton<IAuthorizationHandler, SuperAdminHandler>();

            services.AddSingleton<DataProtectionPurposeStrings>();
        }

        //private void options(GoogleOptions obj)
        //{
        //    throw new NotImplementedException();
        //}

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.e
        public void Configure(IApplicationBuilder app, IHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Error");
                app.UseStatusCodePagesWithReExecute("/Error/{0}");
            }
            app.UseStaticFiles();
            //app.UseMvcWithDefaultRoute();
            //app.UseRouting();
            app.UseAuthentication();
            app.UseMvc(routes =>
            {
                routes.MapRoute("default", "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}

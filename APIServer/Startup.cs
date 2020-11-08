using System;
using System.Text;
using APIServer.Authorization;
using APIServer.Identity;
using APIServer.Models;
using APIServer.Services;
using APIServer.Supporting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;

namespace APIServer
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {

            //context for AppUser
            services.AddDbContext<AppuserDBContext>(options =>
               options.UseSqlServer(
                   Configuration.GetConnectionString("AppUserDBContextConnection")));
            //context for Nowrthwind
            services.AddDbContext<NorthwindContext>(options =>
               options.UseSqlServer(
                   Configuration.GetConnectionString("NorthwindContextConnection")));

            services.AddScoped<IAccountService, AccountService>();
            services.AddScoped<IOrderService, OrderService>();

            services.AddControllers();
            //redirection to HTTPS
            services.AddHttpsRedirection(options =>
            {
                options.HttpsPort = 5001;
                options.RedirectStatusCode = StatusCodes.Status307TemporaryRedirect;
            });

            services.AddIdentity<AppUser, IdentityRole>()
                .AddRoleManager<RoleManager<IdentityRole>>()
                   .AddEntityFrameworkStores<AppuserDBContext>()
                       .AddDefaultTokenProviders();

            services.AddAuthentication(options => 
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            }) 
                .AddJwtBearer(options =>
                {
                    options.RequireHttpsMetadata = false;
                    options.SaveToken = true;
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidateAudience = false,
                        ValidateLifetime = true,
                        ValidateIssuerSigningKey = true,
                        ValidIssuer = Configuration["Jwt:Issuer"],
                        ValidAudience = Configuration["Jwt:Audience"],
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["Jwt:SecretKey"])),
                        ClockSkew = TimeSpan.Zero
                    };
                });



            services.AddAuthorization(config =>
            {
                config.AddPolicy(Policies.Admin, Policies.AdminPolicy());
                config.AddPolicy(Policies.VD, Policies.VDPolicy());
                config.AddPolicy(Policies.Employee, Policies.EmployeePolicy());
            });

            // Default Password settings.
            services.Configure<IdentityOptions>(options =>
            {
                options.Password.RequireDigit = true;
                options.Password.RequireLowercase = true;
                options.Password.RequireNonAlphanumeric = true;
                options.Password.RequireUppercase = true;
                options.Password.RequiredLength = 12;
                options.Password.RequiredUniqueChars = 1;
            });
            services.AddControllers().AddNewtonsoftJson(options =>
                    options.SerializerSettings.ReferenceLoopHandling = Newtonsoft.Json.ReferenceLoopHandling.Ignore
                );
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseHttpsRedirection();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();


            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}

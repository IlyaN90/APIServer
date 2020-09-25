using APIServer.Migrations;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace APIServer.Identity
{
    public class AppuserDBContext : IdentityDbContext<AppUser>
    {
        public AppuserDBContext(DbContextOptions<AppuserDBContext> options)
            : base(options)
        {

        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            /*builder.Entity<AppUser>()
                .HasIndex(u => u.Id)
                .IsUnique();*/

            builder.Entity<AppUser>()
                .HasOne(a => a.JToken)
                .WithOne(b => b.appUser)
                .HasPrincipalKey<AppUser>(c => c.Id);
            ;
            builder.Entity<AppUser>()
                .HasOne(a => a.RefreshToken)
                .WithOne(b => b.appUser)
                .HasPrincipalKey<AppUser>(c => c.Id);
         }
    }
}

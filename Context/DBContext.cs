using Microsoft.EntityFrameworkCore;
using PUBLIC_KEY_INFRASTRUCTURE.Entities;
using System.Collections.Generic;
using System.Reflection.Emit;

namespace PUBLIC_KEY_INFRASTRUCTURE.Context
{
    // DATABASE SETTINGS AND ENTITY FRAMEWORK CONFIGURATION
    public class DBContext : DbContext
    {
        private readonly IConfiguration config;

        // DB CONTEXT OPTIONS
        public DBContext(DbContextOptions<DBContext> dbContextOptions)
        {
            this.ChangeTracker.LazyLoadingEnabled = false;
            config = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
                .Build();
            
        }

        public DbSet<Users> Users { get; set; }
        public DbSet<Messages> Messages { get; set; }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {

            optionsBuilder.UseSqlServer(connectionConfiguration.connectionString);
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {

            modelBuilder.Entity<Users>(entity =>
            {
                entity.HasKey(e => e.id);
            });

            modelBuilder.Entity<Messages>(entity =>
            {
                entity.HasKey(e => e.id);
            });



        }
    }
}



using Microsoft.EntityFrameworkCore;
using PUBLIC_KEY_INFRASTRUCTURE.Context;

namespace PUBLIC_KEY_INFRASTRUCTURE
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // SERVICES

            builder.Services.AddControllers();
            
            builder.Services.AddEndpointsApiExplorer();

            // ENTITY FRAMEWORK DBCONTEXT CONFIGURATION
            builder.Services.AddDbContext<DBContext>(
                option => option.UseSqlServer(connectionConfiguration.connectionString));
            builder.Services.AddSwaggerGen();

            var app = builder.Build();

            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger(); // ADD SWAGGER UI 
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();

            app.UseAuthorization();

            app.MapControllers();

            app.Run();
        }
    }
}

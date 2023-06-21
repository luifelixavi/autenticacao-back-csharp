using Microsoft.AspNetCore.Mvc;

namespace Autenticacao.API.Configuration
{
    public static class APIConfiguration
    {
        public static void AddApiConfiguration(this IServiceCollection services)
        {
            

        }

        public static void UseApiConfiguration(this IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}

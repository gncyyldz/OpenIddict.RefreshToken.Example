using Microsoft.AspNetCore.Authentication.JwtBearer;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);


builder.Services.AddControllers();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = builder.Configuration["AuthenticationSettings:Authority"];
        options.Audience = builder.Configuration["AuthenticationSettings:Audience"];
        options.RequireHttpsMetadata = false;

        options.Events = new()
        {
            OnTokenValidated = async context =>
            {
                if (context.Principal?.Identity is ClaimsIdentity claimsIdentity)
                {
                    Claim? scopeClaim = claimsIdentity.FindFirst("scope");
                    if (scopeClaim is not null)
                    {
                        claimsIdentity.RemoveClaim(scopeClaim);
                        claimsIdentity.AddClaims(scopeClaim.Value.Split(" ").Select(s => new Claim("scope", s)).ToList());
                    }
                }

                await Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AccessReadPolicy", policy => policy.RequireClaim("scope", "read"));
    options.AddPolicy("AccessWritePolicy", policy => policy.RequireClaim("scope", "write"));
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();

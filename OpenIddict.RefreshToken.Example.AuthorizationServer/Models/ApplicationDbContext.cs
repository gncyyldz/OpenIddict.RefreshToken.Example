using Microsoft.EntityFrameworkCore;

namespace OpenIddict.RefreshToken.Example.AuthorizationServer.Models
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions options) : base(options)
        {
        }
    }
}

using Microsoft.EntityFrameworkCore;

namespace OpenIddict.RefreshToken.Example.Client1.Models
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions options) : base(options)
        {
        }
    }
}

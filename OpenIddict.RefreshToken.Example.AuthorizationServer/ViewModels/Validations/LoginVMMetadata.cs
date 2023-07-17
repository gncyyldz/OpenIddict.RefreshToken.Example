using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace OpenIddict.RefreshToken.Example.AuthorizationServer.ViewModels.Validations
{
    public class LoginVMMetadata
    {
        [Required(ErrorMessage = "Lütfen kullanıcı adını boş geçmeyiniz...")]
        [DisplayName("Kullanıcı Adı")]
        public string Username { get; set; }
        [Required(ErrorMessage = "Lütfen şifreyi boş geçmeyiniz...")]
        [DisplayName("Şifre")]
        public string Password { get; set; }
    }
}

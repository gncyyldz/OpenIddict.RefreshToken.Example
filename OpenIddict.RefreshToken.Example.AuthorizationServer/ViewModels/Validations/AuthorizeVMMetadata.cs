using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace OpenIddict.RefreshToken.Example.AuthorizationServer.ViewModels.Validations
{
    public class AuthorizeVMMetadata
    {
        [Required(ErrorMessage = "Lütfen uygulama adını boş geçmeyiniz...")]
        [DisplayName("Uygulama Adı")]
        public string ApplicationName { get; set; }
        [Required(ErrorMessage = "Lütfen scopes'ları boş geçmeyiniz...")]
        [DisplayName("Scopes")]
        public string Scopes { get; set; }
        [Required(ErrorMessage = "Lütfen button değerini boş geçmeyiniz...")]
        [DisplayName("Button")]
        public string Button { get; set; }
    }
}

using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace OpenIddict.RefreshToken.Example.AuthorizationServer.ViewModels.Validations
{
    public class ClientCreateVMMetadata
    {
        [Required(ErrorMessage = "Lütfen client id'yi boş geçmeyiniz...")]
        [DisplayName("Client Id")]
        public string ClientId { get; set; }
        [Required(ErrorMessage = "Lütfen client secret'ı boş geçmeyiniz...")]
        [DisplayName("Client Secret")]
        public string ClientSecret { get; set; }
        [Required(ErrorMessage = "Lütfen display name'i boş geçmeyiniz...")]
        [DisplayName("Display Name")]
        public string DisplayName { get; set; }
        [Required(ErrorMessage = "Lütfen redirect url'i boş geçmeyiniz...")]
        [DisplayName("Redirect URL")]
        public string RedirectUrl { get; set; }
        [Required(ErrorMessage = "Lütfen post logout redirect uri'i boş geçmeyiniz...")]
        [DisplayName("Post Logout Redirect Uri")]
        public string? PostLogoutRedirectUri { get; set; }
    }
}

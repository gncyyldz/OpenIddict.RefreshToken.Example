using Microsoft.AspNetCore.Mvc;
using OpenIddict.RefreshToken.Example.AuthorizationServer.ViewModels.Validations;

namespace OpenIddict.RefreshToken.Example.AuthorizationServer.ViewModels
{
    [ModelMetadataType(typeof(AuthorizeVMMetadata))]
    public class AuthorizeVM
    {
        public string ApplicationName { get; set; }
        public string Scopes { get; set; }
        public string Button { get; set; }
    }
}

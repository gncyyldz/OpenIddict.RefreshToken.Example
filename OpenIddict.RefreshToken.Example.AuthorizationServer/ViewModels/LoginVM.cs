using Microsoft.AspNetCore.Mvc;
using OpenIddict.RefreshToken.Example.AuthorizationServer.ViewModels.Validations;
using System.ComponentModel.DataAnnotations;

namespace OpenIddict.RefreshToken.Example.AuthorizationServer.ViewModels
{
    [ModelMetadataType(typeof(LoginVMMetadata))]
    public class LoginVM
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }
}

using Auth.Models;

namespace Auth
{
    public interface IAuthService
    {
        public Task<User> Login(string email, string password, string scope);
        public Task<User> Register(User user);
    }
}
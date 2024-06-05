namespace Auth.Exceptions;

public class AuthErrorException : Exception
{
  public AuthErrorException(string message) : base(message)
  {

  }
}

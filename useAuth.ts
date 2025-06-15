import { SimpleJwtLogin } from 'simple-jwt-login'

const AUTH_CODE = 'YOUR_AUTH_CODE'
const WP_URL = 'YOUR_WP_URL'
const WP_PATH = '/simple-jwt-login/v1';

export const useAuth = () => {
  const user = useState('user', () => null)
  const isLoading = useState('authLoading', () => false)
  const error = useState('authError', () => null)

  const simpleJwtLogin = new SimpleJwtLogin(
    WP_URL,  
    WP_PATH,                                  
  )

  const login = async (email: string, password: string) => {
    isLoading.value = true
    error.value = null

    try {

      let params = {
        email: email,
        password: password,
      }

      const loginData = await simpleJwtLogin.authenticate(params, AUTH_CODE )
 
      const response = JSON.parse(loginData)
      if (response.success) {
        await fetch('/wp-json/cookiesetter/v1/set-cookie', {
          method: 'POST',
          credentials: 'include',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ token: response.data.jwt }), 
        })
       
      } else {
        throw new Error(response.message || 'Login fehlgeschlagen')
      }
    } catch (err: any) {
      error.value = err?.message || 'Login fehlgeschlagen'
    } finally {
      isLoading.value = false
    }
  }


  const register = async (email: string, password: string) => {
    isLoading.value = true
    error.value = null

    try {

      let params = {
        email: email,
        password: password,
      }
      const result = await simpleJwtLogin.registerUser(params, AUTH_CODE)
      const response = JSON.parse(result)
      if (!response.success) {
        throw new Error(response.message || 'Registrierung fehlgeschlagen')
      }

      // Optional: automatisch einloggen nach Registrierung
      // await login(email, password)

    } catch (err: any) {
      error.value = err?.message || 'Registrierung fehlgeschlagen'
    } finally {
      isLoading.value = false
    }
  }

  return {
    user,
    isLoading,
    error,
    login,
    register,
    isLoggedIn: computed(() => !!user.value),
  }
}

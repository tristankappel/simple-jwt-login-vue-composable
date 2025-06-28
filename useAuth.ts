import { SimpleJwtLogin, type AuthenticateInterface, type RegisterUserInterface, type ResetPasswordInterface, type ChangePasswordInterface  } from 'simple-jwt-login'

const AUTH_CODE = 'YOUR_AUTH_CODE'
const WP_URL = 'YOUR_WP_URL'
const WP_PATH = '/simple-jwt-login/v1';

export const useAuth = () => {
  
  const isLoading = ref(false)
  const error = ref(null)

  const simpleJwtLogin = new SimpleJwtLogin(
    WP_URL,  
    WP_PATH,                                  
  )

  // Login
  const login = async (email: string, password: string) => {
    isLoading.value = true
    error.value = null

    try {
      const params = {
        email: email,
        password: password,
      } as AuthenticateInterface;

      const result = simpleJwtLogin.authenticate(params, AUTH_CODE )

      if (!result) throw new Error('Login fehlgeschlagen.')
      const response = JSON.parse(result)

      localStorage.setItem('wp_user_id', response.wp_user_id)
      localStorage.setItem('wp_user_role', response.wp_user_role)
  

      if (response.success) {
        
      const res = await fetch(WP_URL + '/wp-json/cookiesetter/v1/set-cookie', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: response.data.jwt }),
      })

      const json = await res.json()
      const maxAge = 14 * 24 * 60 * 60; // 14 Tage in Sekunden
      document.cookie = `csrf-token=${json.csrfToken}; Path=/; SameSite=Lax; Max-Age=${maxAge}`;
        
       
      } else {
        throw new Error(response.data.message)
      }
    } catch (err: any) {
      error.value = err?.message
    } finally {
      isLoading.value = false
    }
  }

  // Registration
  const register = async (email: string, password: string) => {
    isLoading.value = true
    error.value = null

    try {
      const params = {
        email: email,
        password: password,
      } as RegisterUserInterface;

      const result = simpleJwtLogin.registerUser(params, AUTH_CODE)
      
      if (!result) throw new Error('Registrierung fehlgeschlagen.')
      const response = JSON.parse(result)

      if (!response.success) {
        throw new Error(response.data.message)
      }

    } catch (err: any) {
      error.value = err?.message
    } finally {
      isLoading.value = false
    }
  }

  // Logout
  const logout = async () => {
    await fetch(WP_URL + '/wp-json/cookiesetter/v1/remove-cookie', {
      method: 'POST',
      credentials: 'include', 
    })
    localStorage.removeItem('wp_user_id')
    localStorage.removeItem('wp_user_role')
    document.cookie = `csrf-token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; SameSite=Lax; Secure`;
  }

  // Get Password Reset Code
  const getPasswordResetCode = async (email: string) => {
    isLoading.value = true
    error.value = null

    try {
      const params = {
        email: email,
      } as ResetPasswordInterface;

      const result = simpleJwtLogin.resetPassword(params, AUTH_CODE)
      
      if (!result) throw new Error('Passwort Reset Code Erzeugung fehlgeschlagen.')
      const response = JSON.parse(result)

      if (!response.success) {
        throw new Error(response.data.message)
      }

    } catch (err: any) {
      error.value = err?.message
    } finally {
      isLoading.value = false
    }
  }

  // Reset Password
  const resetPassword = async (email: string, code: string, password: string) => {
  isLoading.value = true
  error.value = null

    try {
      const params = {
        email: email,
        new_password: password,
        code: code
      } as ChangePasswordInterface;

      const result = simpleJwtLogin.changePassword(params, AUTH_CODE)
      
      if (!result) throw new Error('Passwort Reset fehlgeschlagen.')
      const response = JSON.parse(result)

      if (!response.success) {
        throw new Error(response.data.message)
      }

    } catch (err: any) {
      error.value = err?.message
    } finally {
      isLoading.value = false
    }
  }

  return {
    isLoading,
    error,
    login,
    logout,
    register,
    getPasswordResetCode,
    resetPassword
  }
}

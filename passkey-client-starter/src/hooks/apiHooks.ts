import { User } from '@sharedTypes/DBTypes';
import fetchData from '@/lib/fetchData';
import { LoginResponse, UserResponse } from '@sharedTypes/MessageTypes';
import {
  startAuthentication,
  startRegistration,
} from '@simplewebauthn/browser';
import {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/types';

const useUser = () => {
  const getUserByToken = async (token: string) => {
    const options = {
      headers: {
        Authorization: 'Bearer ' + token,
      },
    };
    return await fetchData<UserResponse>(
      import.meta.env.VITE_AUTH_API + '/users/token/',
      options,
    );
  };

  const getUsernameAvailable = async (username: string) => {
    return await fetchData<{ available: boolean }>(
      import.meta.env.VITE_AUTH_API + '/users/username/' + username,
    );
  };

  const getEmailAvailable = async (email: string) => {
    return await fetchData<{ available: boolean }>(
      import.meta.env.VITE_AUTH_API + '/users/email/' + email,
    );
  };

  return { getUserByToken, getUsernameAvailable, getEmailAvailable };
};

const usePasskey = () => {
  const postUser = async (
    user: Pick<User, 'username' | 'password' | 'email'>,
  ) => {
    const options: RequestInit = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(user),
    };

    const registrationResponse = await fetchData<{
      email: string;
      options: PublicKeyCredentialCreationOptionsJSON;
    }>(import.meta.env.VITE_PASSKEY_API + '/auth/setup', options);

    const attResp = await startRegistration(registrationResponse.options);

    const data = {
      email: registrationResponse.email,
      registrationOptions: attResp,
    };

    const verifyOptions = {
      ...options,
      body: JSON.stringify(data),
    };

    return await fetchData<UserResponse>(
      import.meta.env.VITE_PASSKEY_API + '/auth/verify',
      verifyOptions,
    );
  };

  const postLogin = async (email: string) => {
    const loginOptions = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ email }),
    };

    const authenticationResponse =
      await fetchData<PublicKeyCredentialRequestOptionsJSON>(
        import.meta.env.VITE_PASSKEY_API + '/auth/login-setup',
        loginOptions,
      );

    const attResp = await startAuthentication(authenticationResponse);
    const verifyOptions = {
      ...loginOptions,
      body: JSON.stringify({
        email,
        authResponse: attResp,
      }),
    };

    return await fetchData<LoginResponse>(
      import.meta.env.VITE_PASSKEY_API + '/auth/login-verify',
      verifyOptions,
    );
  };

  return { postUser, postLogin };
};

export { useUser, usePasskey };
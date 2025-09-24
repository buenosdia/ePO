import React, { createContext, useContext, useMemo, useState } from 'react';
import { setAccessToken, logout as apiLogout } from '../lib/api';

type Claims = {
  sub: string;
  tenant_slug: string;
  app_roles?: string[];
  exp: number;
};

type AuthState = {
  token: string | null;
  claims: Claims | null;
  login: (token: string) => void;
  logout: () => void;
};

const AuthContext = createContext<AuthState | undefined>(undefined);

function decodeClaims(token: string): Claims | null {
  try {
    const [, payload] = token.split('.');
    const json = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
    return JSON.parse(json);
  } catch {
    return null;
  }
}

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [token, setToken] = useState<string | null>(() => sessionStorage.getItem('epo_access_token'));
  const [claims, setClaims] = useState<Claims | null>(() => (token ? decodeClaims(token) : null));

  const login = (nextToken: string) => {
    setAccessToken(nextToken);
    setToken(nextToken);
    setClaims(decodeClaims(nextToken));
  };

  const logout = () => {
    apiLogout();
    setToken(null);
    setClaims(null);
  };

  const value = useMemo(() => ({ token, claims, login, logout }), [token, claims]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('Auth context missing');
  return ctx;
}

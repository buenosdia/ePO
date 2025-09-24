import axios from 'axios';

const AUTH_URL = import.meta.env.VITE_AUTH_URL ?? 'http://localhost:4000';
const REST_URL = import.meta.env.VITE_POSTGREST_URL ?? 'http://localhost:3001';

const api = axios.create({ baseURL: REST_URL, timeout: 10000 });
let accessToken = sessionStorage.getItem('epo_access_token') ?? '';

export function setAccessToken(token: string | null) {
  accessToken = token ?? '';
  if (token) {
    sessionStorage.setItem('epo_access_token', token);
  } else {
    sessionStorage.removeItem('epo_access_token');
  }
}

api.interceptors.request.use((config) => {
  if (accessToken) {
    config.headers = config.headers ?? {};
    config.headers.Authorization = `Bearer ${accessToken}`;
  }
  return config;
});

export async function loginLocal(tenant: string, username: string, password: string) {
  const { data } = await axios.post(`${AUTH_URL}/auth/local`, { tenant, username, password });
  setAccessToken(data.token);
  return data;
}

export async function loginLdap(tenant: string, username: string, password: string) {
  const { data } = await axios.post(`${AUTH_URL}/auth/ldap`, { tenant, username, password });
  setAccessToken(data.token);
  return data;
}

export function logout() {
  setAccessToken(null);
}

export { api };

import React, { createContext, useContext, useState } from 'react';
import type { User } from '../types';

interface AuthContextType {
  token: string | null;
  user: User | null;
  login: (token: string, role: string, username: string) => void;
  logout: () => void;
  isAuthenticated: boolean;
}

const AuthContext = createContext<AuthContextType>({} as AuthContextType);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [token, setToken] = useState<string | null>(() => localStorage.getItem('token'));
  const [user, setUser] = useState<User | null>(() => {
    const stored = localStorage.getItem('attcksmith_user');
    return stored ? JSON.parse(stored) : null;
  });

  const login = (newToken: string, role: string, username: string) => {
    const userData = { username, role: role as User['role'] };
    localStorage.setItem('token', newToken);
    localStorage.setItem('attcksmith_user', JSON.stringify(userData));
    setToken(newToken);
    setUser(userData);
  };

  const logout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('attcksmith_user');
    setToken(null);
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ token, user, login, logout, isAuthenticated: !!token && !!user }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => useContext(AuthContext);

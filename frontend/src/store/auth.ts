import { create } from 'zustand';

interface AuthState {
  token: string | null;
  user: { id: string; username: string } | null;
  setAuth: (token: string, user: { id: string; username: string }) => void;
  logout: () => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  token: localStorage.getItem('core_token'),
  user: null,
  setAuth: (token, user) => {
    localStorage.setItem('core_token', token);
    set({ token, user });
  },
  logout: () => {
    localStorage.removeItem('core_token');
    set({ token: null, user: null });
  },
}));

// Alias for convenience
export const useAuth = useAuthStore;

import { render, screen } from '@testing-library/react';
import { getAuthMode } from '../../lib/authMode';
import Login from '../../pages/login';

jest.mock('next/router', () => ({
  useRouter: () => ({
    replace: jest.fn(),
  }),
}));

jest.mock('next-auth/react', () => ({
  useSession: () => ({ data: null, status: 'unauthenticated' }),
  signIn: jest.fn(),
}));

jest.mock('../../lib/authSession', () => ({
  clearAuthState: jest.fn(),
  decodeJwtPayload: jest.fn(),
  isTokenExpired: jest.fn(),
  refreshTokenOnce: jest.fn(),
  setToken: jest.fn(),
}));

jest.mock('../../lib/authMode');

describe('Login page auth-mode handling', () => {
  test('renders the local API key form when the backend reports local mode', async () => {
    getAuthMode.mockResolvedValue('local');
    render(<Login />);

    expect(await screen.findByPlaceholderText('API key')).toBeInTheDocument();
    expect(screen.queryByText(/Sign in with Microsoft/i)).not.toBeInTheDocument();
  });

  test('renders Sign in with Microsoft when the backend genuinely reports entra mode', async () => {
    getAuthMode.mockResolvedValue('entra');
    render(<Login />);

    expect(await screen.findByText(/Sign in with Microsoft/i)).toBeInTheDocument();
  });

  test('a failed auth-mode lookup shows a backend-unreachable error, never a Microsoft sign-in button', async () => {
    getAuthMode.mockRejectedValue(new Error('auth mode lookup failed 502'));
    render(<Login />);

    expect(await screen.findByText(/Can't reach the backend/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument();
    // The previous bug: this exact failure silently rendered a non-functional
    // "Sign in with Microsoft" button, indistinguishable from a real Entra
    // deployment.
    expect(screen.queryByText(/Sign in with Microsoft/i)).not.toBeInTheDocument();
  });
});

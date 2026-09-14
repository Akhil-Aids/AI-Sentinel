import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { loginUser, mfaVerifyLogin } from '../api';

export default function LoginPage() {
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [otp, setOtp] = useState('');
  const [partialToken, setPartialToken] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [info, setInfo] = useState('');

  const onSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setInfo('');
    setLoading(true);
    try {
      const data = await loginUser(username, password);
      if (data.mfa_required) {
        setPartialToken(data.partial_token);
        setInfo(`Second factor required for ${data.username}. Enter the 6-digit TOTP code.`);
        return;
      }
      setInfo(`Welcome, ${data.username} (${data.role}). Session valid ${data.expires_in}s.`);
      setTimeout(() => navigate('/', { replace: true }), 400);
    } catch (err) {
      setError(err.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  const onOtp = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const data = await mfaVerifyLogin(partialToken, otp);
      setInfo(`Welcome, ${data.username} (${data.role}). Session valid ${data.expires_in}s.`);
      setTimeout(() => navigate('/', { replace: true }), 400);
    } catch (err) {
      setError(err.message || 'Verification failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen login-bg text-slate-100 flex items-center justify-center p-4">
      {partialToken ? (
        <form onSubmit={onOtp} className="panel w-full max-w-md">
          <h1 className="text-2xl font-bold text-accent">AI Sentinel</h1>
          <p className="text-sm text-slate-300 mt-1">Authenticator verification</p>
          {error ? <p className="text-danger text-sm mt-3">{error}</p> : null}
          {info ? <p className="text-emerald-300 text-sm mt-3">{info}</p> : null}
          <label className="block mt-4 text-sm">6-digit TOTP code</label>
          <input className="input mt-1 font-mono tracking-[0.5em]" value={otp} maxLength={6}
            onChange={(e) => setOtp(e.target.value.replace(/\D/g, ''))} autoFocus autoComplete="one-time-code" />
          <button className="btn mt-4 w-full" type="submit" disabled={loading}>
            {loading ? 'Verifying…' : 'Verify & Sign In'}
          </button>
          <button type="button" className="mt-2 w-full text-center text-xs text-slate-500 hover:text-slate-300"
            onClick={() => { setPartialToken(''); setOtp(''); setInfo(''); }}>Back</button>
        </form>
      ) : (
        <form onSubmit={onSubmit} className="panel w-full max-w-md">
          <h1 className="text-2xl font-bold text-accent">AI Sentinel</h1>
          <p className="text-sm text-slate-300 mt-1">SOC Console — real-time detection &amp; incident response.</p>
          <p className="text-xs text-slate-500 mt-1">Bootstrap admin credentials are printed to <code className="text-slate-400">backend/app/bootstrap_admin.txt</code> on first run.</p>

          <label className="block mt-4 text-sm">Username</label>
          <input className="input mt-1" value={username} onChange={(e) => setUsername(e.target.value)} autoFocus />

          <label className="block mt-3 text-sm">Password</label>
          <input className="input mt-1" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />

          {error ? <p className="text-danger text-sm mt-3">{error}</p> : null}
          {info ? <p className="text-emerald-300 text-sm mt-3">{info}</p> : null}

          <button className="btn mt-4 w-full" type="submit" disabled={loading}>
            {loading ? 'Signing in…' : 'Sign In'}
          </button>
        </form>
      )}
    </div>
  );
}
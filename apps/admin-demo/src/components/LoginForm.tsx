import { useState } from "react";
import type { LoginPayload } from "../lib/api";

type LoginFormProps = {
  loading: boolean;
  onSubmit(payload: LoginPayload): Promise<void>;
};

export function LoginForm({ loading, onSubmit }: LoginFormProps) {
  const [email, setEmail] = useState("admin@aegis.local");
  const [password, setPassword] = useState("Admin!234567");
  const [otpCode, setOtpCode] = useState("");

  return (
    <form
      className="glass-card login-card"
      onSubmit={async (event) => {
        event.preventDefault();
        await onSubmit({ email, password, otpCode: otpCode || undefined });
      }}
    >
      <div>
        <p className="eyebrow">Acesso inicial</p>
        <h2>Entrar no console AegisCore</h2>
        <p className="muted">
          Use a conta demo para estudar sessão segura, eventos, políticas e auditoria.
        </p>
      </div>

      <label>
        Email
        <input value={email} onChange={(event) => setEmail(event.target.value)} type="email" />
      </label>

      <label>
        Senha
        <input
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          type="password"
        />
      </label>

      <label>
        OTP TOTP opcional
        <input
          value={otpCode}
          onChange={(event) => setOtpCode(event.target.value)}
          inputMode="numeric"
          pattern="[0-9]*"
          placeholder="000000"
        />
      </label>

      <button disabled={loading} type="submit">
        {loading ? "Autenticando..." : "Entrar"}
      </button>

      <p className="demo-note">
        Demo: `admin@aegis.local` / `Admin!234567`
      </p>
    </form>
  );
}


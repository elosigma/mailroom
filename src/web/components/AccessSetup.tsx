import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import type { ApiError } from "../api";

/** Clean login screen with Email + Static Password for Mailroom. */
export function AccessSetup(props: { error: ApiError; onRetry: () => void; retrying: boolean }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [loginError, setLoginError] = useState<string | null>(null);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!email.trim() || !password.trim()) return;
    setLoading(true);
    setLoginError(null);
    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.trim(), password: password.trim() }),
      });
      const data = (await res.json().catch(() => ({}))) as { ok?: boolean; error?: string };
      if (!res.ok || !data.ok) {
        setLoginError(data.error || "Nieprawidłowy e-mail lub hasło");
        setLoading(false);
        return;
      }
      props.onRetry();
    } catch {
      setLoginError("Błąd połączenia z serwerem. Spróbuj ponownie.");
      setLoading(false);
    }
  };

  return (
    <div className="flex h-dvh min-h-[560px] items-center justify-center overflow-y-auto bg-canvas px-4 py-10 text-foreground">
      <div className="w-full max-w-[400px] rounded-2xl border bg-background p-6 shadow-sm sm:p-8">
        <div className="flex items-center gap-2.5">
          <img
            src="/brand/mailroom.png"
            alt=""
            width={24}
            height={24}
            className="h-6 w-6 shrink-0 object-contain"
          />
          <h1 className="text-[19px] font-semibold tracking-tight">Poczta antekch.uk</h1>
        </div>
        <p className="mt-2 text-[13.5px] leading-5 text-muted-foreground">
          Zaloguj się swoim adresem e-mail i stałym hasłem.
        </p>

        <form onSubmit={handleSubmit} className="mt-6 space-y-4">
          <div className="space-y-1.5">
            <label htmlFor="login-email" className="block text-[13px] font-medium text-foreground">
              Adres e-mail
            </label>
            <Input
              id="login-email"
              type="text"
              placeholder="np. ola@antekch.uk"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              autoComplete="username"
              autoFocus
              required
              disabled={loading || props.retrying}
            />
          </div>

          <div className="space-y-1.5">
            <label htmlFor="login-password" className="block text-[13px] font-medium text-foreground">
              Hasło
            </label>
            <Input
              id="login-password"
              type="password"
              placeholder="Wpisz hasło…"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              required
              disabled={loading || props.retrying}
            />
          </div>

          {loginError && (
            <p role="alert" className="rounded-lg bg-destructive/10 px-3 py-2 text-[13px] text-destructive">
              {loginError}
            </p>
          )}

          <Button
            type="submit"
            className="w-full"
            disabled={loading || props.retrying || !email.trim() || !password.trim()}
          >
            {loading || props.retrying ? "Logowanie…" : "Zaloguj się"}
          </Button>
        </form>
      </div>
    </div>
  );
}

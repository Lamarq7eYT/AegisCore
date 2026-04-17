import { useEffect, useState } from "react";
import { LoginForm } from "./components/LoginForm";
import { SecurityConsole } from "./components/SecurityConsole";
import { api } from "./lib/api";

export default function App() {
  const [loading, setLoading] = useState(false);
  const [principal, setPrincipal] = useState<Record<string, unknown> | null>(null);
  const [session, setSession] = useState<Record<string, unknown> | null>(null);
  const [events, setEvents] = useState<Array<Record<string, unknown>>>([]);
  const [audit, setAudit] = useState<Array<Record<string, unknown>>>([]);
  const [policies, setPolicies] = useState<Array<Record<string, unknown>>>([]);
  const [riskSummary, setRiskSummary] = useState<Record<string, unknown> | null>(null);
  const [policyDecision, setPolicyDecision] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = async () => {
    const [sessionResponse, eventsResponse, auditResponse, policiesResponse, riskSummaryResponse] =
      await Promise.all([
        api.currentSession(),
        api.securityEvents(),
        api.audit(),
        api.policies(),
        api.riskSummary()
      ]);

    setPrincipal((sessionResponse.principal as Record<string, unknown>) ?? null);
    setSession((sessionResponse.session as Record<string, unknown>) ?? null);
    setEvents(eventsResponse.events);
    setAudit(auditResponse.entries);
    setPolicies(policiesResponse.policies);
    setRiskSummary(riskSummaryResponse);
  };

  useEffect(() => {
    void (async () => {
      try {
        const me = await api.me();
        if (me.principal) {
          await refresh();
        }
      } catch {
        setPrincipal(null);
      }
    })();
  }, []);

  if (!principal) {
    return (
      <main className="app-shell">
        <div className="background-orb background-left" />
        <div className="background-orb background-right" />
        <LoginForm
          loading={loading}
          onSubmit={async (payload) => {
            setLoading(true);
            setError(null);
            try {
              await api.login(payload);
              await refresh();
            } catch (loginError) {
              setError(loginError instanceof Error ? loginError.message : "Falha ao autenticar.");
            } finally {
              setLoading(false);
            }
          }}
        />
        {error ? <div className="banner-error">{error}</div> : null}
      </main>
    );
  }

  return (
    <main className="app-shell">
      <div className="background-orb background-left" />
      <div className="background-orb background-right" />
      {error ? <div className="banner-error">{error}</div> : null}
      <SecurityConsole
        principal={principal}
        session={session}
        events={events}
        audit={audit}
        policies={policies}
        riskSummary={riskSummary}
        policyDecision={policyDecision}
        onRefresh={async () => {
          setError(null);
          try {
            await refresh();
          } catch (refreshError) {
            setError(refreshError instanceof Error ? refreshError.message : "Falha ao atualizar.");
          }
        }}
        onEvaluatePolicy={async () => {
          setError(null);
          try {
            const response = await api.evaluatePolicy({
              resource: "admin",
              action: "write",
              requestAttributes: {
                reason: "demo-evaluation"
              },
              resourceAttributes: {
                environment: "demo"
              }
            });
            setPolicyDecision(response.decision);
          } catch (evaluationError) {
            setError(
              evaluationError instanceof Error
                ? evaluationError.message
                : "Falha ao avaliar policy."
            );
          }
        }}
        onLogout={async () => {
          setError(null);
          try {
            await api.logout();
            setPrincipal(null);
            setSession(null);
            setEvents([]);
            setAudit([]);
            setPolicies([]);
            setRiskSummary(null);
            setPolicyDecision(null);
          } catch (logoutError) {
            setError(logoutError instanceof Error ? logoutError.message : "Falha ao encerrar sessão.");
          }
        }}
      />
    </main>
  );
}


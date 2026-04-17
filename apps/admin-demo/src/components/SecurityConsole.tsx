type SecurityConsoleProps = {
  principal: Record<string, unknown> | null;
  session: Record<string, unknown> | null;
  events: Array<Record<string, unknown>>;
  audit: Array<Record<string, unknown>>;
  policies: Array<Record<string, unknown>>;
  riskSummary: Record<string, unknown> | null;
  policyDecision: Record<string, unknown> | null;
  onEvaluatePolicy(): Promise<void>;
  onRefresh(): Promise<void>;
  onLogout(): Promise<void>;
};

function pretty(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

export function SecurityConsole(props: SecurityConsoleProps) {
  return (
    <div className="console-shell">
      <header className="hero">
        <div>
          <p className="eyebrow">AegisCore v1</p>
          <h1>Console defensivo híbrido</h1>
          <p className="muted">
            Painel didático para estudar autenticação, anti-abuse, autorização contextual,
            trilhas de auditoria e sinais de risco.
          </p>
        </div>

        <div className="hero-actions">
          <button onClick={() => void props.onRefresh()} className="ghost-button">
            Atualizar
          </button>
          <button onClick={() => void props.onEvaluatePolicy()}>Avaliar policy</button>
          <button onClick={() => void props.onLogout()} className="danger-button">
            Encerrar sessão
          </button>
        </div>
      </header>

      <section className="grid two-up">
        <article className="glass-card">
          <h2>Principal</h2>
          <pre>{pretty(props.principal)}</pre>
        </article>
        <article className="glass-card">
          <h2>Sessão</h2>
          <pre>{pretty(props.session)}</pre>
        </article>
      </section>

      <section className="grid two-up">
        <article className="glass-card">
          <h2>Resumo de risco</h2>
          <pre>{pretty(props.riskSummary)}</pre>
        </article>
        <article className="glass-card">
          <h2>Resultado de policy</h2>
          <pre>{pretty(props.policyDecision)}</pre>
        </article>
      </section>

      <section className="grid three-up">
        <article className="glass-card">
          <h2>Eventos de segurança</h2>
          <pre>{pretty(props.events)}</pre>
        </article>
        <article className="glass-card">
          <h2>Auditoria</h2>
          <pre>{pretty(props.audit)}</pre>
        </article>
        <article className="glass-card">
          <h2>Policies</h2>
          <pre>{pretty(props.policies)}</pre>
        </article>
      </section>
    </div>
  );
}


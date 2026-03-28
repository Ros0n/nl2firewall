import React, { useEffect, useRef, useState } from "react";
import { Shield } from "lucide-react";
import { usePipeline } from "./hooks/usePipeline.js";
import { getNetworkContext } from "./api/client.js";
import ChatTurn from "./components/ChatTurn.jsx";
import ChatInput from "./components/ChatInput.jsx";

export default function App() {
  const {
    sessions,
    networkContext,
    setNetworkContext,
    isSubmitting,
    submit,
    approve,
    sendFeedback,
  } = usePipeline();

  const bottomRef = useRef(null);
  const [backendOk, setBackendOk] = useState(true);

  // ── Check if a network context is already loaded on the backend ─────────────
  useEffect(() => {
    getNetworkContext()
      .then((data) => {
        if (data.loaded) {
          setNetworkContext({
            network_name: data.network_name,
            entity_count: data.entity_count,
          });
        }
      })
      .catch(() => setBackendOk(false));
  }, [setNetworkContext]);

  // ── Scroll to bottom whenever sessions change ────────────────────────────────
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [sessions]);

  const networkLoaded = !!networkContext;

  const handleUploaded = (data) => {
    setNetworkContext({
      network_name: data.network_name,
      entity_count: data.entity_count,
    });
  };

  return (
    <div className="app">
      {/* ── Top bar ─────────────────────────────────────────────────────────── */}
      <header className="topbar">
        <div className="topbar__brand">
          <Shield size={20} className="topbar__icon" />
          <span className="topbar__title">NL2Firewall</span>
          <span className="topbar__subtitle">Natural Language → Cisco ACL</span>
        </div>

        <div className="topbar__right">
          {!backendOk && (
            <span className="topbar__status topbar__status--error">
              ● Backend unreachable
            </span>
          )}
          {networkLoaded && (
            <span className="topbar__status topbar__status--ok">
              ● {networkContext.network_name}
            </span>
          )}
        </div>
      </header>

      {/* ── Chat area ───────────────────────────────────────────────────────── */}
      <main className="chat-area">
        {sessions.length === 0 ? (
          <div className="chat-empty">
            <div className="chat-empty__icon">
              <Shield size={40} />
            </div>
            <h2 className="chat-empty__heading">
              Describe a firewall rule in plain English
            </h2>
            <p className="chat-empty__sub">
              {networkLoaded
                ? `Network context loaded: ${networkContext.network_name}. Type an intent below to get started.`
                : "Upload a network context file using the 📎 button below, then type your intent."}
            </p>
          </div>
        ) : (
          <div className="chat-messages">
            {sessions.map((session, i) => (
              <ChatTurn
                key={session.id}
                session={session}
                onApprove={approve}
                onFeedback={sendFeedback}
                isLatest={i === sessions.length - 1}
              />
            ))}
            <div ref={bottomRef} />
          </div>
        )}
      </main>

      {/* ── Input bar ───────────────────────────────────────────────────────── */}
      <footer className="input-bar">
        <div className="input-bar__inner">
          <ChatInput
            onSubmit={submit}
            onUploaded={handleUploaded}
            disabled={isSubmitting}
            networkLoaded={networkLoaded}
          />
        </div>
      </footer>
    </div>
  );
}

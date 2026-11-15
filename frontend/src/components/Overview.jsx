import React from 'react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  ShieldX, 
  FileText, 
  Wrench, 
  Clock, 
  EyeOff, 
  Activity, 
  Play, 
  ArrowRight,
  RefreshCw,
  Server
} from 'lucide-react';

export default function Overview({ overview, health, loading, onRefresh, onNavigate }) {
  const stats = overview || {
    total_analyzed_prompts: 0,
    allow_decisions: 0,
    sanitize_decisions: 0,
    block_decisions: 0,
    documents_scanned: 0,
    tool_authorization_requests: 0,
    tool_deny_decisions: 0,
    tool_require_approval_decisions: 0,
    tool_execution_attempts: 0,
    pending_approvals: 0,
    privacy_findings: 0,
    recent_security_event_count: 0,
  };

  const isHealthy = health?.status === 'healthy';

  return (
    <div className="space-y-8">
      {/* Top Banner / System Health */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 p-5 rounded-2xl glass-panel border border-slate-800">
        <div className="flex items-center gap-4">
          <div className={`p-3 rounded-xl ${isHealthy ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'}`}>
            <Server className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-lg font-semibold text-white">PromptShield Runtime Gateway</h2>
              <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium ${
                isHealthy ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-800/50' : 'bg-amber-950/80 text-amber-300 border border-amber-800/50'
              }`}>
                <span className={`w-1.5 h-1.5 rounded-full ${isHealthy ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}`}></span>
                {health?.status ? health.status.toUpperCase() : 'CONNECTING'}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Active Security Engine: <span className="text-slate-200 font-mono">v{health?.version || '1.0.0'}</span> • Analysis Context Store: <span className="text-cyan-400 font-mono">Server-Authoritative</span>
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={onRefresh}
            disabled={loading}
            className="inline-flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-medium bg-slate-800/80 hover:bg-slate-700/80 text-slate-300 border border-slate-700/60 transition-all disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh Telemetry
          </button>
          <button
            onClick={() => onNavigate('playground')}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold transition-all shadow-lg shadow-cyan-500/20"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            Live Security Playground
          </button>
        </div>
      </div>

      {/* Primary KPI Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Analyzed Prompts Card */}
        <div className="p-5 rounded-2xl glass-card relative overflow-hidden group">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium uppercase tracking-wider text-slate-400">Prompts Inspected</span>
            <div className="p-2 rounded-lg bg-blue-500/10 text-blue-400">
              <Activity className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-white font-mono">{stats.total_analyzed_prompts}</span>
            <span className="text-xs text-slate-500">session total</span>
          </div>
          <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs font-mono">
            <span className="text-emerald-400 flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
              {stats.allow_decisions} Allow
            </span>
            <span className="text-amber-400 flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-amber-400"></span>
              {stats.sanitize_decisions} Sanitize
            </span>
            <span className="text-rose-400 flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-rose-400"></span>
              {stats.block_decisions} Block
            </span>
          </div>
        </div>

        {/* Tool Authorizations */}
        <div className="p-5 rounded-2xl glass-card relative overflow-hidden group">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium uppercase tracking-wider text-slate-400">Tool Governance</span>
            <div className="p-2 rounded-lg bg-purple-500/10 text-purple-400">
              <Wrench className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-white font-mono">{stats.tool_authorization_requests}</span>
            <span className="text-xs text-slate-500">requests</span>
          </div>
          <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs font-mono">
            <span className="text-rose-400">{stats.tool_deny_decisions} Denied</span>
            <span className="text-amber-400">{stats.tool_require_approval_decisions} Approval</span>
            <span className="text-cyan-400">{stats.tool_execution_attempts} Executed</span>
          </div>
        </div>

        {/* Pending Approvals */}
        <div 
          onClick={() => onNavigate('approvals')}
          className="p-5 rounded-2xl glass-card relative overflow-hidden group cursor-pointer hover:border-amber-500/40 transition-colors"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium uppercase tracking-wider text-slate-400">Human Approvals</span>
            <div className={`p-2 rounded-lg ${stats.pending_approvals > 0 ? 'bg-amber-500/20 text-amber-400 animate-pulse' : 'bg-slate-800 text-slate-400'}`}>
              <Clock className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-white font-mono">{stats.pending_approvals}</span>
            <span className="text-xs text-amber-400 font-medium">pending review</span>
          </div>
          <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-400 group-hover:text-amber-300 transition-colors">
            <span>High/Critical privilege queue</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </div>
        </div>

        {/* Privacy & RAG Scanning */}
        <div className="p-5 rounded-2xl glass-card relative overflow-hidden group">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium uppercase tracking-wider text-slate-400">Privacy & Documents</span>
            <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400">
              <EyeOff className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-white font-mono">{stats.privacy_findings}</span>
            <span className="text-xs text-slate-500">secrets/PII redacted</span>
          </div>
          <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs font-mono text-slate-400">
            <span>RAG Docs Scanned: <span className="text-slate-200">{stats.documents_scanned}</span></span>
            <span>Total Events: <span className="text-slate-200">{stats.recent_security_event_count}</span></span>
          </div>
        </div>
      </div>

      {/* Feature Navigation Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="p-6 rounded-2xl glass-card border border-slate-800/80 flex flex-col justify-between">
          <div>
            <div className="w-10 h-10 rounded-xl bg-cyan-500/10 text-cyan-400 flex items-center justify-center mb-4">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <h3 className="text-base font-semibold text-white">Live Threat Inspector</h3>
            <p className="text-xs text-slate-400 mt-2 leading-relaxed">
              Test prompts against rule-based heuristic patterns, TF-IDF logistic regression classifier, and regex credential/PII filters with instant risk scoring.
            </p>
          </div>
          <button
            onClick={() => onNavigate('playground')}
            className="mt-6 flex items-center justify-between w-full text-xs font-semibold text-cyan-400 hover:text-cyan-300 pt-4 border-t border-slate-800/60"
          >
            <span>Open Prompt & RAG Playground</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </div>

        <div className="p-6 rounded-2xl glass-card border border-slate-800/80 flex flex-col justify-between">
          <div>
            <div className="w-10 h-10 rounded-xl bg-purple-500/10 text-purple-400 flex items-center justify-center mb-4">
              <Wrench className="w-5 h-5" />
            </div>
            <h3 className="text-base font-semibold text-white">Tool Authorization Sandbox</h3>
            <p className="text-xs text-slate-400 mt-2 leading-relaxed">
              Simulate model tool calls under strict server-side analysis binding, RBAC controls, path traversal defenses, and human approval constraints.
            </p>
          </div>
          <button
            onClick={() => onNavigate('playground')}
            className="mt-6 flex items-center justify-between w-full text-xs font-semibold text-purple-400 hover:text-purple-300 pt-4 border-t border-slate-800/60"
          >
            <span>Test Tool Intent Binding</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </div>

        <div className="p-6 rounded-2xl glass-card border border-slate-800/80 flex flex-col justify-between">
          <div>
            <div className="w-10 h-10 rounded-xl bg-amber-500/10 text-amber-400 flex items-center justify-center mb-4">
              <Activity className="w-5 h-5" />
            </div>
            <h3 className="text-base font-semibold text-white">Scientific Benchmarks</h3>
            <p className="text-xs text-slate-400 mt-2 leading-relaxed">
              Inspect verified machine-readable Day 8.5 hardened benchmark metrics: 100% tool governance containment, stratified accuracy, and confusion matrices.
            </p>
          </div>
          <button
            onClick={() => onNavigate('benchmarks')}
            className="mt-6 flex items-center justify-between w-full text-xs font-semibold text-amber-400 hover:text-amber-300 pt-4 border-t border-slate-800/60"
          >
            <span>View Verified Benchmark Results</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
}
